"""Capture complete endpoint debugger API byte streams without guest state writes.

RSP __init__ only connects/configures the socket; wrapping it afterwards misses
no application bytes. QMP wraps the file before greeting/capabilities. Original
protocol methods remain inherited. This records host traffic, not a USB trace or
a claim of calibrated inter-instance event timing.
"""
from pathlib import Path
import hashlib
import json
import socket
import time

class ByteLedger:
    def __init__(self,directory,name,scope="MCU_debugger_API_connections_only"):
        self.directory=Path(directory)
        self.name=name
        self.scope=scope
        self.files={d:(self.directory/f"{name}-{d}.bin").open("xb") for d in ("tx","rx")}
        self.offsets={"tx":0,"rx":0}
        self.log=(self.directory/f"{name}-io.jsonl").open("x")
        self.errors=[]
        self.closed=False
    def bytes(self,direction,data):
        self.files[direction].write(data)
        off=self.offsets[direction];self.offsets[direction]+=len(data)
        self.event("bytes",direction=direction,offset=off,bytes=len(data))
    def event(self,event,**fields):
        self.log.write(json.dumps({"event":event,"host_monotonic_ns":time.monotonic_ns(),**fields})+"\n")
    def error(self,operation,error):
        value={"operation":operation,"type":type(error).__name__,"message":str(error)}
        self.errors.append(value);self.event("error",**value)
    def finish(self):
        if self.closed:return
        self.closed=True
        for f in self.files.values():f.close()
        self.event("ledger_closed",stream_bytes=self.offsets,errors=self.errors);self.log.close()
    def summary(self):
        assert self.closed
        records={}
        for d in ("tx","rx"):
            p=self.directory/f"{self.name}-{d}.bin";b=p.read_bytes()
            records[d]={"path":str(p),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
        return {"schema":"z6ii-debugger-api-byte-ledger/1","connection":self.name,"streams":records,
                "closed":self.closed,"IO_errors":self.errors,"complete_successful_IO_capture":not self.errors,
                "scope":self.scope,"peer_clocks_synchronized":False}

class RecordingSocket:
    def __init__(self,sock,ledger):self.raw,self.ledger=sock,ledger
    def sendall(self,data,*args,**kwargs):
        self.ledger.event("sendall_attempt",requested_bytes=len(data))
        try:self.raw.sendall(data,*args,**kwargs)
        except Exception as error:self.ledger.error("sendall",error);raise
        self.ledger.bytes("tx",data)
    def recv(self,*args,**kwargs):
        try:data=self.raw.recv(*args,**kwargs)
        except Exception as error:self.ledger.error("recv",error);raise
        self.ledger.bytes("rx",data);return data
    def __getattr__(self,name):return getattr(self.raw,name)

class RecordingFile:
    def __init__(self,file,ledger):self.raw,self.ledger=file,ledger
    def write(self,data):
        self.ledger.event("file_write_attempt",requested_bytes=len(data))
        try:n=self.raw.write(data)
        except Exception as error:self.ledger.error("file.write",error);raise
        if n is None or n!=len(data):self.ledger.error("file.write",RuntimeError("partial or unknown write"))
        if n is not None:self.ledger.bytes("tx",data[:n])
        return n
    def readline(self):
        try:data=self.raw.readline()
        except Exception as error:self.ledger.error("file.readline",error);raise
        self.ledger.bytes("rx",data);return data
    def __getattr__(self,name):return getattr(self.raw,name)

def audited_remote(remote_class):
    class AuditedRemote(remote_class):
        def __init__(self,port,ledger):
            super().__init__(port)
            self.sock=RecordingSocket(self.sock,ledger)
    return AuditedRemote

def audited_qmp(qmp_class):
    class AuditedQMP(qmp_class):
        def __init__(self,port,ledger):
            self.socket=socket.create_connection(("127.0.0.1",port),5)
            self.file=RecordingFile(self.socket.makefile("rwb",buffering=0),ledger)
            json.loads(self.file.readline())
            self.command("qmp_capabilities")
    return AuditedQMP
