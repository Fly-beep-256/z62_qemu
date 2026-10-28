"""Check retained virtual battery causality and UART byte conservation."""
import json


def audit_virtual_battery(peer, checked, ref):
    if peer.get('clock') != 'QEMU_CLOCK_VIRTUAL':
        return dict(status='host_endpoint; virtual_timing_not_claimed'), []
    issues = []

    def need(condition, message):
        if not condition:
            issues.append('Virtual battery: ' + message)

    table_path = checked(peer['compiled_contracts'])
    table = json.loads(table_path.read_text())
    ledger_path = checked(peer['events_evidence'])
    rows = [json.loads(line) for line in ledger_path.read_text().splitlines()]
    closure_path = checked(peer['endpoint_raw_closure'])
    closure = json.loads(closure_path.read_text())
    tx = checked(peer['streams']['public_TX']).read_bytes()
    rx = checked(peer['streams']['synthetic_RX']).read_bytes()
    need(table.get('schema') == 'ex1850.virtual-battery-contracts/1', 'contract schema differs')
    need(table.get('clock') == peer.get('clock'), 'table clock differs')
    need(table.get('specification') == peer.get('specification'), 'table specification differs')
    need(table.get('immutable_inputs_compiled_before_guest_start') is True,
         'pre-launch immutable-input contract missing')
    need(peer.get('contract_sha256') == peer['compiled_contracts']['sha256'] ==
         closure.get('contract_sha256'), 'loaded contract hash differs')
    need(peer.get('endpoint_closed') is True and peer.get('host_worker_created') is False,
         'in-process endpoint closure missing')
    requests, replies = {}, {}
    last_request_ns = -1
    for event in rows:
        phase, seq = event.get('phase'), event.get('sequence')
        need(phase in ('request', 'reply') and type(seq) is int, 'invalid ledger phase/sequence')
        if phase not in ('request', 'reply') or type(seq) is not int:
            continue
        container = requests if phase == 'request' else replies
        need(seq not in container, 'duplicate ' + phase + ' sequence')
        container[seq] = event
        index = event.get('contract_index')
        need(type(index) is int and 0 <= index < len(table['contracts']), 'invalid contract index')
        if type(index) is not int or not 0 <= index < len(table['contracts']):
            continue
        contract = table['contracts'][index]
        need(event.get('clock') == 'QEMU_CLOCK_VIRTUAL', 'ledger uses a different clock')
        need(event.get('public_TX') == contract['TX'] and event.get('synthetic_RX') == contract['RX'],
             'ledger bytes differ from the immutable selected contract')
        start = event.get('TX_byte_offset', -1)
        frame = bytes.fromhex(contract['TX'])
        need(type(start) is int and start >= 0 and tx[start:start + len(frame)] == frame,
             'ledger TX offset does not identify retained wire bytes')
        complete, due = event.get('TX_complete_virtual_ns'), event.get('reply_due_virtual_ns')
        need(type(complete) is int and type(due) is int, 'missing virtual TX/reply timestamp')
        if type(complete) is not int or type(due) is not int:
            continue
        need(due == complete + table['turnaround_ns'] and
             event.get('turnaround_ns') == table['turnaround_ns'], 'reply deadline differs from declared turnaround')
        need(event.get('private_RAM_RNG_or_register_access') is False and
             event.get('guest_state_written') is False, 'wire event reports private state access')
        if phase == 'request':
            need(seq == len(requests) and complete >= last_request_ns,
                 'request order or completed-TX time regressed')
            last_request_ns = complete
            need(event.get('virtual_ns') == complete and
                 event.get('source') == 'completed_guest_UART_TX_frame', 'request lacks completed-TX causality')
        else:
            need(seq in requests, 'reply preceded its completed TX')
            previous = requests.get(seq, {})
            need(all(event.get(k) == previous.get(k) for k in
                 ('contract_index', 'TX_byte_offset', 'TX_complete_virtual_ns', 'reply_due_virtual_ns')),
                 'reply differs from the queued completed request')
            need(event.get('virtual_ns') == due and
                 event.get('dispatch_observed_virtual_ns', -1) >= due,
                 'reply was offered before its virtual deadline')
            start = event.get('RX_byte_offset', -1)
            frame = bytes.fromhex(contract['RX'])
            need(type(start) is int and start >= 0 and rx[start:start + len(frame)] == frame,
                 'ledger RX offset does not identify retained wire bytes')
            admitted, lost = event.get('RX_admitted_delta', -1), event.get('RX_discarded_delta', -1)
            need(type(admitted) is int and type(lost) is int and admitted >= 0 and lost >= 0 and
                 admitted + lost == len(frame), 'reply offer bytes are unaccounted')
            if event.get('receiver_enabled_at_offer') is False:
                need(admitted == 0 and lost == len(frame), 'disabled receiver retained reply bytes')
    need(len(replies) == peer.get('replies'), 'reply ledger count differs from closure')
    need(len(requests) - len(replies) == peer.get('pending_replies'), 'pending reply counter differs')
    final = peer['final_USART1']
    need(final['wire_TX_bytes'] == len(tx) and final['wire_RX_bytes'] == len(rx),
         'final UART wire counters differ from retained streams')
    need(final['RX_completed'] + final['RX_queued'] + final['RX_discarded'] == len(rx),
         'final UART completed/queued/discarded bytes do not conserve offered input')
    need(final['RX_completed'] + final['RX_queued'] <= final['RX_admitted'],
         'completed UART input exceeds admitted bytes')
    return dict(status='verified_virtual_wire_contract' if not issues else 'failed_or_incomplete',
        contracts=ref(table_path), ledger=ref(ledger_path), raw_closure=ref(closure_path),
        requests=len(requests), replies=len(replies), pending=peer.get('pending_replies'),
        turnaround_ns=table['turnaround_ns'], physical_turnaround_verified=False,
        final_USART1=final,
        scope='Declared external timing and UART conservation; original firmware acceptance is separate'), issues
