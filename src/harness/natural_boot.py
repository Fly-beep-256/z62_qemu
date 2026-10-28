"""Two original Z6II application entry points with explicit device inputs.

Hardware breakpoints resume the original instruction without CPU/ROM patches.
Optional recorded RAM replays are reported as diagnostic fixtures: region47 at
its original DMA submission, and region0B/0C at the original common runtime entry.
Neither establishes first-stage Boot ROM or original Flash-loader execution.
The native MCU may run separately on the shared bus. Menu/display acceptance
requires observed pixels and original input handling.
"""
import argparse
import hashlib
import json
import os
import select
import time
import traceback
from pathlib import Path

from coupled_dual import create_backing
from host_env import ROOT
from probe_z6ii import Probe, peer_parameter_layout, peer_data_layout
from run_evidence import process_summary

OUT = ROOT / "results/standalone-dual"
ABORT_OBSERVERS = {
    "master": {0x10103610: "first original master data-abort handler",
               0x1010365C: "first original master prefetch-abort handler"},
    "slave": {0x100350C0: "first original slave data-abort handler",
              0x1003510C: "first original slave prefetch-abort handler"},
}

SOURCE50_FAULT_OBSERVERS = {
    0x10200AF4: "original phase announcement flag1 set call",
    0x10200AF8: "original phase announcement returned before enum4 notification",
    0x102422D6: "original phase announcement mask3 waiter entry",
    0x102422E0: "original phase announcement mask15 waiter entry",
    0x10324B90: "original upper event interface phase initializer",
    0x10324C02: "original phase2 upper callback pointer source",
    0x10324C04: "original phase2 upper callback binder call",
    0x103D04C0: "original bind-once upper callback old slot read",
    0x103D04C6: "original bind-once upper callback slot store",
    0x103D04C8: "original bind-once upper callback slot store completed",
    0x103CF818: "original event dispatcher before source50 fallback",
    0x103CF8E2: "original fallback callback pointer load",
    0x103CF8EA: "original fallback BX before possible null target",
}
SOURCE50_COPY_OBSERVERS = {
    0x103A5F6E: "original DMA copy helper entry before ownership check",
    0x103A5F88: "original DMA ownership check returned before branch",
    0x103A5E4E: "original DMA copy internal submit entry",
    0x103C2CCE: "original source item copy helper returned before unchecked continuation",
}
GPIO_ROUTE_OBSERVERS = {
    0x1036AC1A: "original GPIO logical mapping entry",
    0x1036AC1E: "original GPIO halfword mapping before native load",
    0x1036AC22: "original GPIO mapping returned",
    0x10388158: "original GPIO masked writer descriptor entry",
    0x1038817A: "original GPIO masked DATA write before store",
    0x1038817E: "original GPIO one-bit reader descriptor entry",
    0x10388188: "original GPIO DATA read before original load",
    0x1038818A: "original GPIO DATA read returned raw word",
    0x10388192: "original GPIO one-bit reader returned",
    0x10388194: "original GPIO descriptor direction option entry",
}
PHASE2_SERIAL_OBSERVERS = {
    0x107638D0: "original service6 backend phase argument",
    0x1076397C: "original service6 ops factory",
    0x1043E0A2: "original service6 ops setter entry",
    0x1043E0A6: "original service6 ops store completed",
    0x1020555A: "original serial initializer entry",
    0x102055BE: "original serial binder indirect dispatch",
    0x10763992: "original service6 serial binder entry",
    0x1076399A: "original service6 serial binder stores completed",
    0x10205698: "original serial request submission",
}
OBSERVERS = {
    "master": {
        0x10200034: "native RTOS boot task",
        0x10200042: "boot task after hardware setup",
        0x10103610: "master original data abort entry",
        0x1010365C: "master original prefetch abort entry",
        0x10200CAC: "native parallel boot phase",
        0x1038A1E8: "native link configure",
        0x1038A210: "native link initialize",
        0x1038A23E: "native master role setup",
        0x1038A666: "native master handshake",
        0x10200C52: "native master handshake returned",
        0x103156E8: "native image mode configuration",
        0x103033F0: "native image memory initialization",
        0x10324D4E: "native image mode configuration returned",
        0x10324D54: "native image memory initialization returned",
        0x103A58C8: "fixed resource buffer initialization",
        0x103A58DE: "fixed resource pointers stored",
        0x103A5A0C: "startup resource copy entry",
        0x104026D8: "resource service registration wrapper",
        0x104026F0: "resource service initialization wrapper",
        0x10637D16: "native UI resource allocation",
        0x103A5F6E: "native DMA request",
        0x10248300: "native configuration region pointer initialization instruction",
        0x103C13C4: "TEMP configuration pointer setter",
        0x103C130E: "TEMP monitor enable store",
        0x103F3688: "application startup checks",
        0x1020D384: "native system policy state transition",
        0x1043527E: "native EX MCU startup report decoder",
        0x103FBE1E: "native power report receiver",
        0x10247AF2: "application state 2 entry",
        0x1029AC06: "input inhibit setter",
        0x1029AC3C: "input inhibit clearer",
        0x1029AA0A: "normal input forward",
        0x1043A1FE: "GUI input callback",
    },
    "slave": {
        0x10052F74: "native RTOS boot task",
        0x10052F7E: "boot task after hardware setup",
        0x10060CA0: "native link configure",
        0x10060CC8: "native link initialize",
        0x10060CF6: "native slave role setup",
        0x1006111E: "native slave handshake",
        0x10053656: "native slave handshake returned",
        0x100530CC: "slave main loop",
        0x100350C0: "slave original data abort entry",
        0x1003510C: "slave original prefetch abort entry",
    },
}

# Observe the original worker and backend dispatch rather than calling any
# initializer. Repeated dispatch records identify the first unfinished backend.
RESOURCE_OBSERVERS = {
    0x10200CC6: "boot phase native function dispatch",
    0x10200CCA: "boot phase native function returned",
    0x10200CF8: "boot phase original flag wait returned",
    0x102003A6: "phase3 first backend registration wrapper",
    0x102003B6: "phase3 intervening backend registration wrapper",
    0x102003BA: "phase3 resource backend registration wrapper",
    0x102003FA: "phase3 first backend initialization wrapper",
    0x1020040E: "phase3 resource backend initialization wrapper",
    0x102018B8: "first backend group registration",
    0x102018CA: "first backend registration dispatch",
    0x102018CC: "first backend registration returned",
    0x102018E4: "first backend group initialization",
    0x102018F6: "first backend initialization dispatch",
    0x102018F8: "first backend initialization returned",
    0x102019DC: "resource backend group registration",
    0x102019EE: "resource backend registration dispatch",
    0x102019F0: "resource backend registration returned",
    0x10201A12: "resource backend group initialization",
    0x10201A24: "resource backend initialization dispatch",
    0x10201A26: "resource backend initialization returned",
}

SERIAL_OBSERVERS = {
    0x10388440: "native GPIO IRQ67 wrapper",
    0x10388446: "native GPIO IRQ68 wrapper",
    0x1020BCE2: "native MCU RX GPIO interrupt callback",
    0x102433A8: "native SPI pending cause read",
    0x1020B686: "native EX MCU receive worker",
    0x1020B6D4: "native SPI1 receive submission",
    0x1020B6D8: "native SPI1 receive returned",
    0x1020B7E8: "native EX MCU transmit worker",
    0x1020B88A: "native SPI0 transmit submission",
    0x1020B8D2: "native transmit ACK GPIO check",
    0x1020B766: "native serialized receive callback dispatch",
    0x102053E4: "native serial receive business callback",
    0x102055E6: "native reassembled service dispatch",
    0x1020562A: "native decoded service consumer dispatch",
    0x10205618: "native service wire decoder dispatch",
    0x1020663A: "native SYS report callback dispatch",
    0x1020633C: "native SYS manager upper callback dispatch",
    0x10204E30: "native SYS event forward into system policy",
    0x10434EB4: "native EX MCU wire decoder dispatch",
    0x10206CC4: "native EX MCU service0F consumer",
    0x10385F42: "native startup event consumer",
    0x103C2954: "native startup version callback",
    0x103C28D2: "native parent version compare",
}

SLAVE_DEVICE_OBSERVERS = {
    0x1008B0F0: "native slave2B20 configuration sequence",
    0x10089E72: "native slave2B20 mode/control setter",
    0x1008B21E: "native slave2B20 alternate mode4 selection",
    0x1008B238: "native slave2B20 own config update returned",
    0x1008B2B2: "native slave2B20 sequence success-return path",
}

PEER_BUSINESS_OBSERVERS = {
    "master": {
        0x10200CF8: "original master boot-phase flag wait return",
        0x10200190: "original master boot-task idle",
        0x102DE4EC: "original master fill-channel descriptor submission",
        0x1038C09A: "original master reverse-DMA1 completion callback",
        0x1038C104: "original master reverse-DMA1 original wait returned",
    },
    "slave": {
        0x100350C0: "first original slave data-abort handler",
        0x1003510C: "first original slave prefetch-abort handler",
        0x100530CC: "original slave main-loop checkpoint",
        0x10060F10: "original peer receiver callback pointer check",
        0x10060F16: "original peer receiver callback dispatch",
        0x10060F18: "original peer receiver after callback",
        0x10067768: "original peer generic callback into local object queue",
        0x10067710: "original slave local-object worker dispatcher",
        0x100B5D2A: "original type8 business handler",
        0x1008B0F0: "original slave2B20 configuration sequence",
        0x1008B252: "original slave2B200300 control read-modify-write entry",
        0x1008B2B6: "original slave2B20 sequence return instruction",
        0x1008B336: "original slave pipeline initializer",
        0x1008B3FC: "original slave pipeline completion predicate passed",
        0x1008B3F6: "original slave pipeline initializer return result",
        0x100677E2: "original slave type8 completion reply producer",
        0x100A5E0C: "original slave registered initializer callback dispatch",
        0x100A5E10: "original slave registered initializer callback return",
        0x100B5C26: "original slave upper initializer result",
        0x100B5C5A: "original filesystem mount first result",
        0x100B5C80: "original filesystem mount fallback result",
        0x100B5D14: "original upper filesystem operation boolean result",
        0x100B5CFE: "original slave upper initializer failure classification",
        0x1006AB9C: "original slave fill-channel descriptor submission",
        0x100693B6: "original slave fill-channel completion callback",
        0x10069420: "original slave fill-channel original wait returned",
    },
}

POWER_INPUT_OBSERVERS = {
    0x1038CB5C: "native power backend initialization",
    0x1038CB74: "native power backend callback registration dispatch",
    0x10204854: "native service04 power callback registration",
    0x10432230: "native service04 wire03 power decoder",
    0x1020486E: "native service04 decoded report consumer",
    0x1038CAB2: "native power service callback",
    0x1038C942: "native power event flag dispatcher",
    0x103FB60A: "native runtime power report processing",
    0x103FB78E: "native runtime power042D0010 publication",
    0x10431234: "native042D0010 status property consumer",
    0x10430622: "native property4F activation prerequisite store",
    0x1042F91E: "native backend state machine activation",
    0x10436600: "native service02 wire01 KEY decoder",
    0x1038DD44: "native service02 decoded KEY consumer",
    0x1038DC0C: "native KEY report copy",
    0x1020E374: "native SYS event message producer",
    0x103C286C: "native persistent region generation validation",
    0x103C28CC: "native startup generation state write",
    0x103C294E: "native configuration startup status publication",
    0x103C102A: "native TEMP conditional status getter",
    0x10326938: "native application TEMP prerequisite evaluation",
}

POLICY_OBSERVERS = {
    0x10247810: "native state0 entry",
    0x10247898: "native state0 SYS configuration consumer",
    0x10247912: "native state0 application notification consumer",
    0x10247A16: "native state0 SYS configuration decision",
    0x1020D5FA: "native policy callback producing02000003",
    0x1020D364: "native policy queued message submission",
    0x1020CA7A: "native policy queued message consumer",
    0x10204BDA: "native policy outward request callback",
    0x1020DAD2: "native policy outward request routing",
    0x102A7BD0: "native state outward request callback selection",
    0x1043130A: "native05020101 mode request consumer",
    0x1020F876: "native property event backend dispatch",
    0x1043063C: "native backend6 mode initialization request",
    0x103F34B8: "native controller operation5 request",
    0x103F34C2: "native controller operation5 submission returned",
    0x102280F8: "native controller operation admission",
    0x10430890: "native backend6 completion callback",
    0x10430822: "native backend6 operation9 request path",
    0x103F353E: "native controller operation9 request",
    0x103F3548: "native controller operation9 admission returned",
    0x103F02F6: "native operation9 deferred continuation",
    0x104304E4: "native backend6 controller operation callback",
    0x10430676: "native property36 backend6 completion consumer",
    0x1042F86A: "native backend state7 completion request",
    0x103EAA44: "native controller lower mode state transition",
    0x103C724E: "native operation9 group1 command4 construction",
    0x102F30E4: "native lower request event flag callback",
    0x102F2150: "native lower request consumption worker",
    0x102F2180: "native lower command dispatch",
    0x102F20D6: "native lower command4 handler",
    0x1030FD94: "native lower command4 image lifecycle request",
    0x1030F9DC: "native image lifecycle state dispatcher",
    0x1030F954: "native image lifecycle busy prerequisite getter",
    0x1030A956: "native image lifecycle state1D lower request prerequisite",
    0x1030A962: "native image lifecycle lower request prerequisite returned",
    0x10342796: "native lower image controller availability getter",
    0x103A03C0: "native image lifecycle state1D downstream request",
    0x10386960: "native service0D command02 submission",
    0x10386B60: "native service0D upper callback registration",
    0x10386B7C: "native service0D03050020 completion publication",
    0x10386AFE: "native service0D status2 error publication",
    0x1038654C: "native service0D original timer callback",
    0x10386614: "native service0D decoded reply consumer",
    0x1030F1E2: "native image lifecycle MCU completion callback",
    0x10430350: "native backend7 completion callback",
    0x102459E8: "native property4D policy callback selection",
    0x103F023E: "native operation5 deferred continuation",
    0x103C719E: "native operation5 lower request construction",
    0x102F0E1C: "native lower request queue submission",
    0x102F0E22: "native lower request queue result",
    0x102F5372: "native lower request enqueue",
    0x10228B46: "native controller deferred queue worker",
    0x104304C8: "native backend6 activation object gate",
    0x104304D2: "native backend6 power status prerequisite gate",
    0x104304E2: "native backend6 activation gate exit",
}

# Small, passive continuation after the already observed operation9 completion.
# Observe the actual policy pending masks and task callbacks; never supply a
# success result, callback pointer, state transition or guest configuration.
POLICY_FOLLOWUP_OBSERVERS = {
    0x10247898: "native state0 SYS configuration consumer",
    0x10247A16: "native state0 SYS configuration decision",
    0x10247AA8: "native state0 SYS candidate2 selection instruction",
    0x104304E4: "native backend6 controller operation callback",
    0x10430890: "native backend6 completion callback",
    0x10247912: "native state0 application notification consumer",
    0x10247994: "native state0 post-notification candidate selection",
    0x1020DAD2: "native policy outward request routing",
    0x1020CC60: "native policy family03 message dispatch",
    0x1020CC82: "native policy family03 task callback dispatch",
    0x1020CC84: "native policy family03 task callback returned",
    0x102A7CE4: "native state task lifecycle request",
    0x1020DE92: "native policy pending group getter",
    0x1020C988: "native policy group2 pending mask update instruction",
    0x1020C9F6: "native policy group2 deferred continuation dispatch",
    0x102A7D06: "native state task pending getter returned",
    0x1020DEAE: "native policy task completion dependency setter",
    0x102A7D26: "native state task request submitted",
    0x102A7D56: "native state task lower helper returned",
    0x102A7D6A: "native state task pending step store",
    0x102A7D70: "native state task completion continuation",
    0x10247AC2: "native state0 task step callback",
    0x1020D384: "native system policy state transition",
}

# A separate small set for the actual source and conditional clear of group2
# bit0x40. Scalar event parameters are recorded as scalars; neither the message
# payload nor the pending mask is supplied by this observer.
POLICY_GROUP2_SOURCE_OBSERVERS = {
    0x10204B96: "native policy initialization wrapper",
    0x10204BAC: "native policy phase1 group2 bit40 store instruction",
    0x10204BB0: "native policy initialization wrapper return path",
    0x1020E0E8: "native policy family050400 event producer entry",
    0x1020E110: "native policy02000004 message construction entry",
    0x1020E120: "native policy02000004 scalar payload store instruction",
    0x1020E154: "native policy050400 produced message submission",
    0x1020CBDE: "native policy02000004 consumer",
    0x1020CC1C: "native policy02000005 payload decision",
    0x1020CC44: "native policy02000005 bit40 clear preparation",
    0x1020CC4C: "native policy02000005 bit40 clear call",
    0x10204E3C: "native controller event policy wrapper",
    0x1020E3FE: "native policy041000 controller event consumer",
    0x1020F7C0: "native04100007 aggregate prerequisite input",
    0x1020F7D0: "native04100007 low3-bit prerequisite decision",
    0x1020F7DA: "native02000005 changed prerequisite message construction",
    0x1020F7F4: "native02000005 changed prerequisite message submission",
    0x1020C988: "native policy group2 pending mask after update",
    0x1020C9F6: "native policy group2 deferred continuation dispatch",
    0x102A7CE4: "native state task lifecycle request",
    0x102A7D06: "native state task pending getter returned",
    0x1020DEAE: "native policy task completion dependency setter",
    0x104304E4: "native backend6 controller operation callback",
    0x10247912: "native state0 application notification consumer",
    0x1020D384: "native system policy state transition",
}

CONTROLLER_PREREQUISITE_OBSERVERS = {
    0x1022D364: "native controller evaluation inhibit bit clear entry",
    0x1022D376: "native controller evaluation inhibit bit set entry",
    0x103E8E34: "native controller prerequisite evaluation wrapper",
    0x103E8E88: "native controller evaluation inhibit getter returned",
    0x103E8EF8: "native controller prerequisite property query dispatch",
    0x103E8EFC: "native controller prerequisite property result store instruction",
    0x10353C02: "native aggregate property evaluation entry",
    0x103E9496: "native controller prerequisite value comparison",
    0x103E94AA: "native controller04100007 changed value publication",
    0x10204E3C: "native controller event policy wrapper",
    0x1020F7C0: "native04100007 aggregate prerequisite input",
    0x1020CC1C: "native policy02000005 payload decision",
    0x104304E4: "native backend6 controller operation callback",
}

# Follow only naturally executed context producers and the aggregate getter.
# Internal property IDs and notification values are not physical state labels.
CONTROLLER_CONTEXT_OBSERVERS = {
    0x1026D000: "native aggregate context save/reset entry",
    0x1026D04A: "native aggregate context mode reset entry",
    0x1026D064: "native aggregate context mode reset stores completed",
    0x1026D096: "native internal1B28 context reset property store call",
    0x1026D0A4: "native aggregate context mask OR entry",
    0x1026D0B4: "native aggregate context mask OR store completed",
    0x1026D0CE: "native aggregate context mask commit entry",
    0x1026D0EC: "native internal1B28 aggregate commit property store call",
    0x1026D112: "native aggregate context calculation flag setter",
    0x10353C18: "native aggregate context getter returned",
    0x10353C2E: "native aggregate fast path internal1B28 query call",
    0x10353C32: "native aggregate fast path internal1B28 query returned",
    0x10353C38: "native aggregate full calculation path entered",
    0x1034CE5E: "native notification to aggregate context mask converter",
    0x103EFDB0: "native controller context notification1 producer",
    0x1034D156: "native context notification8 producer",
    0x103E8EFC: "native controller aggregate property query returned",
    0x103E94AA: "native controller04100007 changed value publication",
    0x1020F7C0: "native04100007 aggregate prerequisite input",
    0x1020CC1C: "native policy02000005 payload decision",
    0x104304E4: "native backend6 controller operation callback",
}

CONTROLLER_NOTIFICATION_OBSERVERS = {
    0x103EFC48: "native controller upstream event callback",
    0x103EFCAE: "native controller event dependent state calculation",
    0x103EFCD6: "native controller dependent state byte store",
    0x103EFC80: "native controller event deferred callback submission",
    0x103EFBE8: "native controller dependent state notification8 continuation",
    0x1034D156: "native context notification8 producer",
    0x1034CE5E: "native notification to aggregate context mask converter",
    0x1026D0B4: "native aggregate context mask OR store completed",
    0x103D67F2: "native dependent state selector getter",
    0x103D7C4A: "native dependent state triple getter",
    0x103D7C60: "native dependent state selector setter",
    0x1035A3EA: "native dependent state triple classification",
    0x10353C18: "native aggregate context getter returned",
    0x10353C32: "native aggregate fast path internal1B28 query returned",
    0x10353C38: "native aggregate full calculation path entered",
    0x103E94AA: "native controller04100007 changed value publication",
    0x1020F7C0: "native04100007 aggregate prerequisite input",
    0x1020CC1C: "native policy02000005 payload decision",
    0x104304E4: "native backend6 controller operation callback",
}

ORIENTATION_CONFIG_OBSERVERS = {
    0x10201420: "native orientation initialization boot wrapper",
    0x103D79D4: "native orientation initialization dispatcher",
    0x103D7714: "native orientation hardware type0 initialization",
    0x103D7732: "native orientation first configuration pointer gate",
    0x103D7738: "native orientation second configuration pointer gate",
    0x103D777E: "native orientation absent configuration failure path",
    0x103D7928: "native orientation hardware type1 initialization",
    0x103D7968: "native orientation type1 absent configuration failure path",
    0x102052E8: "native orientation configuration notification task",
    0x1020532E: "native resource21 configuration getter returned",
    0x10205348: "native resource57 configuration getter returned",
    0x103D7AA0: "native orientation first ACCELE configuration binder",
    0x103D7AC2: "native orientation second ACCELE configuration binder",
    0x103D7A60: "native initial orientation selector getter returned",
    0x103D7A3C: "native initial orientation sample-validity gate",
    0x103D75D6: "native orientation sample acquisition and publication",
    0x103D6EAE: "native orientation six-byte bus read",
    0x103D76F6: "native orientation first sample validity store",
    0x103EFCD6: "native controller orientation classification store",
    0x1034D156: "native context notification8 producer",
    0x10353C18: "native aggregate context getter returned",
    0x10353C38: "native aggregate full calculation path entered",
}

CONFIG_NOTIFICATION_OBSERVERS = {
    0x10205372: "native orientation configuration subscription initializer",
    0x10205380: "native resource21 lifecycle subscription call",
    0x1020538E: "native resource57 lifecycle subscription call",
    0x102052E8: "native orientation configuration lifecycle callback",
    0x1020530C: "native orientation configuration flag wait returned",
    0x10205368: "native orientation configuration lifecycle flag set call",
    0x1020532E: "native resource21 configuration getter returned",
    0x10205348: "native resource57 configuration getter returned",
    0x103D7AA0: "native orientation first ACCELE configuration binder",
    0x103D7AC2: "native orientation second ACCELE configuration binder",
    0x103A6BE0: "native configuration region service phase dispatcher",
    0x1024821C: "native configuration region address table initializer",
    0x103A6BB6: "native parent configuration load wrapper",
    0x103C1B5E: "native parent configuration load request",
    0x103C1BBE: "native parent configuration load early return",
    0x103C1BC6: "native parent configuration failed load fallback",
    0x103C1BF4: "native parent configuration lifecycle callback dispatch",
    0x103C1C3E: "native parent11 child04400043 lifecycle callback dispatch",
    0x103C28D2: "native parent configuration readiness evaluator",
    0x103C2954: "native startup configuration readiness callback",
    0x103C2944: "native zero synchronization-mask branch before status byte loads",
    0x103A6B66: "native parent configuration result consumer",
}

# A passive timing trace of the original LCD configuration consumer. The
# lifecycle callback waits up to5000ms for flags1|4. Loading regions after that
# callback returned is not a retry and does not publish the panel table.
PEER_PARAMETER_OBSERVERS = {
    0x1006AA32: "original parameter-copy channel0 ISR entry",
    0x1006AA40: "original parameter-copy ISR after status read and acknowledge",
    0x1006AA76: "original parameter-copy ISR callback BX instruction",
    0x100694E6: "original parameter-copy channel0 completion callback entry",
    0x10069500: "original parameter-copy completion eventflag publication call",
    0x10069504: "original parameter-copy completion eventflag publication returned",
    0x10069AEA: "original parameter-copy caller wait entry",
    0x10069552: "original parameter-copy caller wait returned",
}

DISPLAY_CONFIG_OBSERVERS = {
    0x1020526C: "original LCD configuration callback registration",
    0x102051B4: "original LCD configuration lifecycle callback entry",
    0x1020521C: "original LCD configuration wait for mask5 entry",
    0x10205226: "original LCD configuration mask5 wait returned",
    0x10205236: "original LCD region18 getter returned",
    0x10205264: "original LCD configuration region lifecycle flag producer",
    0x104D9F1A: "original display configuration notification",
    0x104840AC: "original LCD panel table pointer producer",
    0x103C1B5E: "original configuration region load request",
    0x103C2954: "original configuration generation startup callback",
}

# Observe the original RAM generation/classification and actual SYS publication.
# No synchronization mask, marker, generation, content or status is supplied.
CONFIG_SYNC_OBSERVERS = {
    0x10201B4C: "native ordinary boot configuration phase wrapper",
    0x103A6BE0: "native configuration phase argument entry",
    0x10248394: "native configuration phase3 metadata refresh entry",
    0x103C318A: "native ordinary parent08 load wrapper",
    0x103C1CB4: "native selector-based parent configuration loader",
    0x103A6B66: "native registered parent08/11/35 lifecycle result consumer",
    0x103C2954: "native SYS0301000A original generation payload callback",
    0x103C28D6: "native configuration synchronization enable load instruction",
    0x103C286C: "native parent RAM generation classification entry",
    0x103C2876: "native parent target RAM getter returned",
    0x103C287E: "native parent descriptor getter returned",
    0x103C288A: "native parent RAM generation word load instruction",
    0x103C28CC: "native parent classification byte store instruction",
    0x103C28D0: "native parent generation and classification return",
    0x103C28E8: "native parent08 generation getter returned to evaluator",
    0x103C28F2: "native parent11 generation getter returned to evaluator",
    0x103C28FC: "native parent35 generation getter returned to evaluator",
    0x103C293A: "native configuration synchronization mask load instruction",
    0x103C294E: "native three configuration status arguments publication tail",
    0x10386304: "native three configuration status arguments SYS publisher",
    0x103C27F6: "native nonzero configuration synchronization mask dispatch",
    0x103C2680: "native parent synchronization preparation entry",
    0x103C1B5E: "native parent configuration load request",
    0x103C1C3E: "native parent11 child04400043 lifecycle callback dispatch",
    0x1020530C: "native orientation configuration flag wait returned",
}

SYS_CONFIG_WIRE_OBSERVERS = {
    0x10386304: "native configuration status SYS event publisher",
    0x10385D48: "native SYS worker configuration-status flag branch",
    0x10385D54: "native SYS worker indirect configuration-status sender call",
    0x10385D56: "native SYS worker configuration-status sender returned",
    0x10206EC6: "native SYS configuration-status adapter",
    0x10206EDC: "native SYS configuration-status transport callback call",
    0x102054FE: "native original serial route send wrapper",
    0x1038607E: "native configuration synchronization transfer submission",
    0x103C27F6: "native configuration synchronization mask dispatch",
    0x103C1B5E: "native parent configuration load request",
    0x1020530C: "native orientation configuration flag wait returned",
}


DMA_ALLOCATION_OBSERVERS = {
    0x10200CF8: "original parallel boot phase flag wait returned",
    0x102004E6: "original boot-worker priority change entry",
    0x102003FA: "original phase2 first-backend initialization entry",
    0x102018F6: "original phase2 first-backend initializer dispatch",
    0x102018F8: "original phase2 first-backend initializer returned",
    0x1020040E: "original phase2 resource-backend initialization entry",
    0x10201A24: "original phase2 resource-backend initializer dispatch",
    0x104026D8: "original resource service registration phase argument",
    0x104026F0: "original resource service initialization phase argument",
    0x10244568: "original phase2 resource service initialization",
    0x10200AC2: "original late-boot task entry",
    0x10200B0E: "original late-boot task calls startup resource copy",
    0x10295EBC: "original copy-DMA descriptor programming",
    0x10295F6C: "original copy-DMA start method",
    0x103A5F6E: "original resource DMA request",
    0x103A58C8: "original fixed resource buffer initialization",
    0x103A58DE: "original fixed resource pointer publication",
    0x103A5A0C: "original startup resource copy entry",
    0x10637D16: "original UI resource allocation",
}

IPUBF_ORIGIN_OBSERVERS = {
    0x104026F0: "original IPUBF resource initialization phase argument",
    0x103A58DE: "original IPUBF destination pointers stored",
    0x103A5A44: "original IPUBF actual DMA submission parameters",
}


def dma_allocation_snapshot(remote, address, registers):
    """Read existing stack and RAM descriptors; never supply a DMA target."""
    import struct
    sp = int(registers["r13"], 16)
    result = dict(stack_address=hex(sp), stack_256bytes=remote.memory(sp, 256).hex(),
        copy_DMA_channel_objects_address="0xc18066f0",
        copy_DMA_channel_objects_hex=remote.memory(0xC18066F0, 4 * 0x24).hex(),
        copy_DMA_register_pointer_tables_address="0xc1806660",
        copy_DMA_register_pointer_tables_hex=remote.memory(0xC1806660, 4 * 0x24).hex(),
        resource_buffer_root=remote.memory(0xC1808CA0, 0x20).hex(),
        resource_service_method_table_address="0xc1808c90",
        resource_service_method_table_hex=remote.memory(0xC1808C90, 16).hex(),
        resource_backend_getter_list_address="0xc185e058",
        resource_backend_getter_list_hex=remote.memory(0xC185E058, 31 * 4).hex(),
        DMA_snapshot_is_read_only=True)
    if address in (0x10295EBC, 0x10295F6C):
        obj = int(registers["r0"], 16)
        if 0xC1800000 <= obj <= 0xC1FFFFDC:
            raw = remote.memory(obj, 0x24)
            result.update(copy_DMA_object_address=hex(obj), copy_DMA_object_hex=raw.hex())
            table = struct.unpack_from('<I', raw, 4)[0]
            if 0xC1800000 <= table <= 0xC1FFFFDC:
                result.update(copy_DMA_register_pointer_table=hex(table),
                    copy_DMA_register_pointers=[hex(v) for v in struct.unpack('<9I', remote.memory(table, 36))])
        if address == 0x10295EBC:
            descriptor = int(registers["r1"], 16)
            if 0xC1800000 <= descriptor <= 0xCDFFFFE0:
                raw = remote.memory(descriptor, 32)
                result.update(copy_DMA_programming_descriptor_address=hex(descriptor),
                    copy_DMA_programming_descriptor_hex=raw.hex(),
                    copy_DMA_count_minus_one=struct.unpack_from('<I', raw, 0)[0],
                    copy_DMA_source=hex(struct.unpack_from('<I', raw, 4)[0]),
                    copy_DMA_destination=hex(struct.unpack_from('<I', raw, 8)[0]))
    return result


GENNOR_LIFECYCLE_OBSERVERS = {
    0x10200630: "original startup invokes user-storage phase0",
    0x101024F0: "original user-storage phase and permission producer",
    0x1010255C: "original region0F header lookup returned",
    0x1010256C: "original region0F header record restore returned",
    0x10101EB0: "original user-storage length and schema gate",
    0x1010203E: "original user-storage schema migration",
    0x101025CA: "original user-storage length/schema gate returned",
    0x1010261A: "original user-storage phase returns after permission production",
    0x10102494: "original user-storage phase subscriber registration",
    0x10100EEE: "original GENNOR dequeue and callback dispatch",
    0x1010234C: "original group3C followup submit",
    0x10294A14: "original service10 transport callback registration",
    0x10294B4E: "original service10 group3C submission method",
    0x10432052: "original service10 command4 encoder",
    0x102421D6: "original service10 result and completion relay",
    0x10102318: "original GENNOR result/completion event consumer",
}


def gennor_lifecycle_snapshot(remote):
    """Read existing RAM only; do not call firmware or supply persistence."""
    import struct
    state = remote.memory(0xC1875304, 0x20)
    words = struct.unpack('<8I', state)
    header = remote.memory(0xC25614E4, 0x14)
    return dict(gennor_lifecycle_state_address="0xc1875304",
        gennor_lifecycle_state_hex=state.hex(),
        gennor_work_in_progress=words[0], gennor_followup_pending=words[1],
        gennor_processed_restore_phase_mask=words[2],
        gennor_user_storage_restore_permission=words[3],
        gennor_permission_lock_uninitialized=words[4],
        gennor_permission_lock_object=words[5], gennor_permission_lock_counter=words[6],
        gennor_queue_count_head_tail=list(struct.unpack('<3I', remote.memory(0xC2407D54, 12))),
        gennor_user_storage_header_hex=header.hex(),
        gennor_user_storage_length_word=struct.unpack_from('<I', header)[0],
        gennor_user_storage_schema_word=struct.unpack('<I', remote.memory(0xC25784E0, 4))[0],
        gennor_configuration_interface_hex=remote.memory(0xC18A7E54, 0x2C).hex(),
        gennor_group3c_hex=remote.memory(0xC257849C, 52).hex(),
        gennor_group3d_hex=remote.memory(0xC25784D0, 16).hex(),
        gennor_snapshot_is_read_only=True,
        gennor_permission_does_not_establish_factory_TEMP_parent_validity=True)


def configuration_sync_snapshot(remote):
    """Read only initialized parent descriptors and their actual RAM tails."""
    import struct
    state = remote.memory(0xC185E548, 0x24)
    payload = remote.memory(0xC20AF0D0, 12)
    parents = []
    for region in (0x08, 0x11, 0x35):
        address = 0xC185EBA8 + region * 0x1C
        raw = remote.memory(address, 0x1C)
        fields = struct.unpack("<7I", raw)
        target, length = fields[2:4]
        item = dict(region_id=hex(region), descriptor_address=hex(address),
                    descriptor_bytes=raw.hex(), descriptor_words=list(fields),
                    RAM_target=hex(target), descriptor_length=length)
        # These are the initialized configuration RAM targets, never MMIO.
        safe_range = any(lo <= target and target + length < hi for lo, hi in
                         ((0xC0000000, 0xC6000000), (0xC8000000, 0xCB000000)))
        if safe_range and 16 <= length <= 0x100000:
            tail_address = target + length - 16
            tail = remote.memory(tail_address, 16)
            item.update(RAM_tail_address=hex(tail_address), RAM_tail_bytes=tail.hex(),
                        RAM_generation_address=hex(target + length - 4),
                        RAM_generation_word=struct.unpack_from("<I", tail, 12)[0])
        else:
            item["RAM_read_deferred_until_descriptor_initialized"] = True
        parents.append(item)
    return dict(configuration_sync_state_address="0xc185e548",
                configuration_sync_state_bytes=state.hex(),
                configuration_status_bytes=list(state[:3]),
                configuration_sync_enabled=struct.unpack_from("<I", state, 4)[0],
                configuration_sync_mask=struct.unpack_from("<I", state, 8)[0],
                configuration_local_generation_words=list(struct.unpack_from("<3I", state, 12)),
                SYS_generation_payload_address="0xc20af0d0",
                SYS_generation_payload_bytes=payload.hex(),
                SYS_generation_payload_words=list(struct.unpack("<3I", payload)),
                configuration_parent_snapshots=parents)


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--integrated", action="store_true")
    parser.add_argument("--legacy-single", action="store_true",
                        help="Causal comparison: old single-guest scripted peer, not two-ended boot")
    parser.add_argument("--label", default="entry-baseline")
    parser.add_argument("--output-dir", type=Path,
                        help="Caller-selected new experiment directory; must not already exist")
    parser.add_argument("--expeed-byte-ledger", action="store_true",
                        help="Save complete per-engine RSP/QMP API bytes in the selected experiment directory")
    parser.add_argument("--stop-both-before-snapshot", action="store_true",
                        help="Stop both EXPEED engines and confirm QMP before final CPU/RAM observations")
    parser.add_argument("--task-observation-plan", type=Path,
                        help="Explicit ROM-bound, finite stopped RAM candidate and saved-stack observation plan")
    parser.add_argument("--seconds", type=float, default=25)
    parser.add_argument("--lcd-snapshot-interval", type=float, default=0,
                        help="Optional wall-second interval for passive master LCD screenshots during execution")
    parser.add_argument("--graphics-capture", action="store_true",
                        help="Diagnostic raw GPU command/texture dumps; disabled by default to conserve disk space")
    parser.add_argument("--qemu-build-manifest", type=Path,
                        help="Explicit digest-verified QEMU build manifest, including a frozen baseline")
    parser.add_argument("--qemu-exception-trace", action="store_true",
                        help="Passive QEMU int/guest_errors log; original guest instructions and fault registers unchanged")
    parser.add_argument("--phase2-serial-trace", action="store_true",
                        help="Observe original service6 phase2 ops and serial binding stores without calling them")
    parser.add_argument("--peer-parameter-trace", action="store_true",
                        help="Passive original slave parameter-copy ISR, callback and waiter; no MMIO reads or guest writes")
    parser.add_argument("--source50-fault-trace", action="store_true",
                        help="Observe original fallback callback loads and BX with source50 records; no guest calls")
    parser.add_argument("--source50-copy-trace", action="store_true",
                        help="Observe original DMA ownership branch and copy return before source notification; no device completion changes")
    parser.add_argument("--boot-tcg-trace", action="store_true",
                        help="Bounded original startup/IPUDRV/HDMI evidence; no guest writes")
    parser.add_argument("--source50-tcg-trace", action="store_true",
                        help="Default-off original master TCG trace; no GDB sites added")
    parser.add_argument("--conditional-seed-only-observers", action="store_true",
                        help="Conditional experiment: retain only the two original slave DMA submission stops needed to seed real region47 RAM")
    parser.add_argument("--gpio-route-trace", action="store_true",
                        help="Observe original logical GPIO mapping and descriptors; never issue an extra MMIO input read")
    parser.add_argument("--mcu-wire-path", type=Path,
                        help="Existing run-local bus shared with a separately running original MCU reset guest")
    parser.add_argument("--mcu-wire-poll-ns", type=int,
                        help="Explicit native MCU transport poll quantum; physical clocks remain unverified")
    parser.add_argument("--mcu-wire-known-wait-ms", type=int,
                        help="Explicit0..5000ms host wait for actual peer GPIO outputs; not measured hardware timing")
    parser.add_argument("--no-observers", action="store_true")
    parser.add_argument("--service0d-trace-only", action="store_true",
                        help="Observe only original service0D callbacks and image lifecycle; no guest calls or state writes")
    parser.add_argument("--resource-trace", action="store_true",
                        help="Passive boot-worker and backend dispatch observations")
    parser.add_argument("--serial-trace", action="store_true",
                        help="Passive original EX MCU receive/transmit/consumer observations")
    parser.add_argument("--slave-device-trace", action="store_true",
                        help="Passive original slave2B20 configuration and caller observations")
    parser.add_argument("--peer-business-trace-only", action="store_true",
                        help="Passive original peer receiver, local object queue and type8 worker; no guest calls or injected completion")
    parser.add_argument("--slave-2b20-control-latch", action="store_true",
                        help="Explicit unmeasured RESET0/writable-bit0 hypothesis at slave2B200300; no computation, status, IRQ or completion fixture")
    parser.add_argument("--slave-pipeline-mode", choices=("config", "complete"),
                        help="Opt-in native slave pipeline config with delayed completion, or no-completion control")
    parser.add_argument("--menu-session", action="store_true",
                        help="Attach menu inputs to original booted master while original slave continues")
    parser.add_argument("--menu-plan", choices=("traversal", "reentry"), default="traversal",
                        help="Diagnostic attached menu plan; final acceptance requires saved-frame review")
    parser.add_argument("--menu-config-region", type=lambda s: int(s, 0),
                        action="append", default=[],
                        help="Additional original resource loads; diagnostic only, no pointer fixture")
    parser.add_argument("--sensor-dependency-trace", action="store_true",
                        help="Passive original sensor resource validation and timed-wait observations")
    parser.add_argument("--tg-event-test", choices=("single", "paired"),
                        help="Explicit nonphysical master TG event condition; default emits no test ticks")
    parser.add_argument("--display-config-trace", action="store_true",
                        help="Additional passive original LCD lifecycle wait/producer timing; no firmware input or retry")
    parser.add_argument("--shared-event-poll-ns", type=int, choices=(1000, 10000, 100000), default=1000,
                        help="Functional host transport poll latency; original guest timers stay unchanged")
    parser.add_argument("--slave-access-ready-line", action="store_true",
                        help="Opt-in raw input bit10 tied to original slave bridge configuration completion")
    parser.add_argument("--slave-sdhci-mode", choices=("no-card", "empty-card", "fat-card"),
                        help="Original slave SDHCI hosts: absent, fresh blank, or fresh FAT16 cards")
    parser.add_argument("--slave-filesystem", choices=("FAT16", "FAT32"), default="FAT16")
    parser.add_argument("--slave-card-capacity-mib", type=int, choices=(256, 4096), default=256)
    parser.add_argument("--master-persistent-input", type=Path,
                        help="Identity-checked manifest for a recorded master external-flash input")
    parser.add_argument("--slave-persistent-input", type=Path,
                        help="Identity-checked manifest for a recorded slave external-flash input")
    parser.add_argument("--power-input-trace", action="store_true",
                        help="Passive original service04/KEY/configuration dependency observations")
    parser.add_argument("--policy-trace", action="store_true",
                        help="Passive state0, native policy messages and outward requests; no notification injection")
    parser.add_argument("--policy-followup-only", action="store_true",
                        help="Observe only state0 task dependencies after operation9; no guest calls or completion fixtures")
    parser.add_argument("--policy-group2-source-only", action="store_true",
                        help="Passively observe the native source, message producer and conditional clear of group2 bit40")
    parser.add_argument("--controller-prerequisite-only", action="store_true",
                        help="Passively trace the actual producer of controller04100007 and its query prerequisites")
    parser.add_argument("--controller-context-only", action="store_true",
                        help="Read-only original context writer and internal1B28 aggregate query observations")
    parser.add_argument("--controller-notification-only", action="store_true",
                        help="Passively trace the missing original context notification8 and its actual upstream events")
    parser.add_argument("--orientation-config-only", action="store_true",
                        help="Read-only original orientation configuration binding, initialization gates and sample acquisition")
    parser.add_argument("--config-notification-only", action="store_true",
                        help="Passively trace original lifecycle registration, configuration flag wait and parent-load sources")
    parser.add_argument("--config-sync-only", action="store_true",
                        help="Read-only original parent RAM generation, synchronization mask and actual SYS status arguments")
    parser.add_argument("--sys-config-wire-only", action="store_true",
                        help="Passively follow original SYS status publication, actual sender adapter and captured wire output")
    parser.add_argument("--gennor-lifecycle-only", action="store_true",
                        help="Read-only original user-storage permission, GENNOR queue and service10 observations")
    parser.add_argument("--dma-allocation-only", action="store_true",
                        help="Read-only original copy-DMA objects, source and destination provenance")
    parser.add_argument("--ipu-resource-origin-trace", action="store_true",
                        help="At most four hits each at original IPUBF phase, pointer store and copy submission")
    parser.add_argument("--initial-resource-startup-barrier", type=Path,
                        help="Hold Slave until Master recorded resources are verified; original connections only")
    parser.add_argument("--policy-group2-watch-only", action="store_true",
                        help="Passive write watchpoint on the original policy group2 mask; no guest memory writes")
    parser.add_argument("--quiet-observers", action="store_true",
                        help="Keep complete observer records on disk without printing every hit")
    parser.add_argument("--loader-runtime-reference-spec", type=Path,
                        help="Read-only full 0B/0C comparison after both EXPEED stop; no RAM replay")
    parser.add_argument("--exmcu-transport", action="store_true",
                        help="Explicit EX MCU GPIO/SPI hypothesis; full MCU firmware boot remains absent")
    parser.add_argument("--exmcu-packet", type=Path,
                        help="Replay identity-checked original EX1850 startup packet through device input")
    parser.add_argument("--exmcu-packet-delay-ms", type=int, default=0,
                        help="Explicit simulated device arrival timing,0..5000ms; no physical MCU timing claim")
    parser.add_argument("--exmcu-sys-version-packet", type=Path,
                        help="Original EX1850 version response to the captured original SYS01 request")
    parser.add_argument("--exmcu-sys-state-packet", type=Path,
                        help="Explicit C-initialized SYS state diagnostic input; physical startup sampling absent")
    parser.add_argument("--exmcu-sys-delay-ms", type=int, default=1000,
                        help="SYS reply timing hypothesis0..5000ms after original request; C-init state100ms later")
    parser.add_argument("--exmcu-key-packet", type=Path,
                        help="Original GPIO-sampled diagnostic KEY input, with matching bounded-origin evidence")
    parser.add_argument("--exmcu-key-delay-ms", type=int, default=2000,
                        help="Explicit peripheral KEY arrival hypothesis0..5000ms from board initialization")
    parser.add_argument("--exmcu-power-packet", type=Path,
                        help="Original C-initialized service04 power diagnostic packet; physical sampling absent")
    parser.add_argument("--exmcu-power-delay-ms", type=int, default=3000,
                        help="Explicit C-initialized power report arrival hypothesis0..5000ms from board initialization")
    parser.add_argument("--exmcu-service0d-packet", type=Path,
                        help="Original GPIO worker wire82 diagnostic reply, only for the exact captured sequence1 request")
    parser.add_argument("--exmcu-service0d-delay-ms", type=int, default=10,
                        help="Explicit original GPIO reply arrival hypothesis0..5000ms after the original request")
    parser.add_argument("--exmcu-service0d-command01-packet", type=Path,
                        help="Original wire81 packet from the explicit phase1 MCU initialization diagnostic; full MCU boot absent")
    parser.add_argument("--exmcu-service0d-command01-delay-ms", type=int, default=10,
                        help="Device arrival delay after the captured original command01/sequence2 request")
    parser.add_argument("--icount-shift", type=int, default=6,
                        help="Explicit instruction timing hypothesis, default6; not a measured Z6II clock")
    parser.add_argument("--peer-buffer-section", action="store_true",
                        help="Explicit one-section master C2900000 to slave42900000 RAM aperture hypothesis")
    parser.add_argument("--peer-data-section", action="store_true",
                        help="Observed master C2C00000 to slave42C00000 RAM aperture; extent from immutable model")
    parser.add_argument("--peer-dma-section", action="store_true",
                        help="Observed master C8300000 RAM to slave28300000 DMA bus-source hypothesis")
    parser.add_argument("--slave-dma-section", action="store_true",
                        help="Observed slave C6B00000 3MiB RAM to master46B00000 DMA source hypothesis")
    parser.add_argument("--peer-parameter-section", action="store_true",
                        help="Complete application RAM pool, master C7F00000 to slave47F00000 fill0 source hypothesis")
    parser.add_argument("--parameter-require-recorded-body", action="store_true",
                        help="Reject unknown parameter bytes; optionally admit original region50 stage8 via pinned read-only references")
    parser.add_argument("--parameter-source-reference-spec", type=Path,
                        help="Pinned recorded bodies used only for byte provenance; never seed guest RAM")
    parser.add_argument("--diagnostic-peer-region47-ram", type=Path,
                        help="Conditional diagnostic only: seed verified region47 RAM at its original second DMA submission; source-loader generation is omitted")
    parser.add_argument("--diagnostic-master-resource-ram", type=Path,
                        help="Explicit two-pass camera region0B/0C RAM replay after original scatter; physical Flash preload is not verified")
    parser.add_argument("--slave-fill-channel1", action="store_true",
                        help="Original slave channel1 byte-copy descriptor, RAM movement and GIC104")
    parser.add_argument("--master-fill-channel1", action="store_true",
                        help="Original master channel1 rectangular zero-fill and GIC104")
    parser.add_argument("--stop-at", type=lambda value: int(value, 0),
                        help="Passive master checkpoint; leave original CPU state paused")
    args = parser.parse_args()
    if args.stop_both_before_snapshot and (not args.integrated or args.legacy_single or args.menu_session):
        parser.error("Two-engine stop observations require original integrated engines without an attached menu session")
    if args.task_observation_plan and not (args.stop_both_before_snapshot and args.expeed_byte_ledger):
        parser.error("Task RAM observation requires the two-engine stop gate and complete debugger byte ledgers")
    # The command, rather than an inherited shell variable, selects this
    # diagnostic event condition and every run records it explicitly.
    os.environ.pop("Z6II_TG_EVENT_TEST", None)
    if args.tg_event_test:
        if not args.integrated:
            parser.error("TG event conditions require the isolated integrated Z6II model")
        os.environ["Z6II_TG_EVENT_TEST"] = args.tg_event_test
    if not 1 <= args.seconds <= 1200:
        parser.error("Each host execution window must be between 1 and 1200 seconds")
    if args.integrated and args.legacy_single:
        parser.error("Integrated and legacy single-guest models are exclusive")
    if not 0 <= args.icount_shift <= 8:
        parser.error("Instruction timing hypothesis must use an icount shift from 0 to 8")
    if args.peer_buffer_section and not args.integrated:
        parser.error("Observed peer buffer section requires the integrated two-ended model")
    if args.peer_data_section and not args.peer_buffer_section:
        parser.error("Observed peer data section requires the integrated peer-buffer section")
    if args.peer_dma_section and not args.peer_data_section:
        parser.error("Observed peer DMA section requires the integrated peer-data section")
    if args.slave_dma_section and not args.peer_dma_section:
        parser.error("Observed slave DMA section requires the integrated peer-DMA section")
    if args.peer_parameter_section and (not args.integrated or not args.peer_data_section):
        parser.error("Peer parameter sections require integrated original peer data")
    if args.parameter_require_recorded_body and not args.peer_parameter_section:
        parser.error("Parameter provenance guard requires the shared parameter pool")
    parameter_reference = None
    if args.parameter_source_reference_spec:
        if not args.parameter_require_recorded_body:
            parser.error("Read-only parameter references require the source guard")
        from parameter_source_reference import inspect_spec
        parameter_reference, _ = inspect_spec(args.parameter_source_reference_spec,
            json.loads(args.qemu_build_manifest.read_text()) if args.qemu_build_manifest else None)
    diagnostic_body = None
    if args.diagnostic_peer_region47_ram:
        if not (args.parameter_require_recorded_body and args.peer_business_trace_only and args.peer_parameter_trace) or args.no_observers:
            parser.error("Conditional region47 RAM seed requires the source guard and original submission/completion observations")
        diagnostic_body = args.diagnostic_peer_region47_ram.resolve(strict=True).read_bytes()
        if len(diagnostic_body) != 0xd8000 or hashlib.sha256(diagnostic_body).hexdigest() != '996d4ae717a00eb76d9b6ee42e92736bdf74069cc44a95af709ab228e0f6b76b':
            parser.error("Conditional region47 seed must be the complete verified D8000h camera RAM body")
    if args.conditional_seed_only_observers and (diagnostic_body is None or args.no_observers):
        parser.error("Seed-only observers require explicit verified diagnostic RAM and are not zero-observer execution")
    recorded_ram_checked, recorded_ram_bodies = None, []
    if args.diagnostic_master_resource_ram:
        if not args.integrated or args.no_observers or args.legacy_single:
            parser.error("Recorded Master resources require original integrated execution and the post-scatter stop")
        from recorded_ram_input import inspect_spec
        original_master = (ROOT / 'inputs/firmware/master-original-with-crc.bin').read_bytes()
        recorded_ram_checked, recorded_ram_bodies = inspect_spec(args.diagnostic_master_resource_ram, original_master)
    if args.initial_resource_startup_barrier and recorded_ram_checked is None:
        parser.error('Initial resource startup barrier requires recorded Master resources')
    loader_runtime_reference = None
    if args.loader_runtime_reference_spec:
        if not args.stop_both_before_snapshot or args.diagnostic_master_resource_ram or args.diagnostic_peer_region47_ram:
            parser.error('Complete Loader audit requires the stop gate and all diagnostic RAM replay disabled')
        from loader_runtime_audit import load_reference
        original_master = (ROOT / 'inputs/firmware/master-original-with-crc.bin').read_bytes()
        loader_runtime_reference = load_reference(args.loader_runtime_reference_spec, original_master)
    if args.ipu_resource_origin_trace and args.no_observers:
        parser.error('IPUBF origin tracing requires passive original-code observers')
    if args.slave_fill_channel1 and (not args.peer_dma_section or not args.slave_sdhci_mode):
        parser.error("Original slave fill channel1 requires observed DMA source and storage model")
    if args.master_fill_channel1 and not args.integrated:
        parser.error("Original master fill channel1 requires the integrated original two-guest model")
    if args.slave_2b20_control_latch and (not args.integrated or args.legacy_single):
        parser.error("Control300 latch hypothesis requires two original integrated engines")
    if args.slave_pipeline_mode and not args.slave_2b20_control_latch:
        parser.error("Pipeline hypothesis requires the explicit slave control latch")
    if args.slave_access_ready_line and args.slave_pipeline_mode != "complete":
        parser.error("Access-ready input hypothesis requires complete bridge model")
    if args.slave_sdhci_mode and not args.slave_access_ready_line:
        parser.error("SDHCI hypothesis requires the explicit slave bridge access line")
    if args.slave_filesystem != "FAT16" and args.slave_sdhci_mode != "fat-card":
        parser.error("FAT32 selection requires fresh formatted virtual cards")
    if args.menu_session and (not args.integrated or args.legacy_single or args.stop_at):
        parser.error("Attached menus require two original integrated engines without an early stop")
    if args.menu_config_region and not args.menu_session:
        parser.error("Additional diagnostic regions require --menu-session")
    if any(not 0 <= value <= 0x50 for value in args.menu_config_region):
        parser.error("Original resource regions must be 0..0x50")
    if (args.exmcu_transport or args.exmcu_packet or args.exmcu_sys_version_packet or args.exmcu_key_packet or args.exmcu_power_packet or args.exmcu_service0d_packet or args.exmcu_service0d_command01_packet) and not args.integrated:
        parser.error("EX MCU transport requires the integrated two-ended model")
    if args.exmcu_packet or args.exmcu_sys_version_packet or args.exmcu_key_packet or args.exmcu_power_packet or args.exmcu_service0d_packet or args.exmcu_service0d_command01_packet:
        args.exmcu_transport = True
    if args.mcu_wire_path:
        if not args.integrated or args.legacy_single or args.exmcu_transport or args.exmcu_sys_state_packet:
            parser.error("Native MCU bus requires two original integrated engines and no diagnostic EXMCU transport/replay")
        if args.mcu_wire_poll_ns is None or not 1 <= args.mcu_wire_poll_ns <= 1000000:
            parser.error("Native MCU bus requires explicit poll quantum1..1000000ns")
    elif args.mcu_wire_poll_ns is not None:
        parser.error("MCU poll quantum requires an explicit run-local bus")
    if args.exmcu_sys_state_packet and not args.exmcu_sys_version_packet:
        parser.error("C-initialized SYS state input requires original SYS version response")
    if not 0 <= args.exmcu_sys_delay_ms <= 5000:
        parser.error("SYS response timing hypothesis must be0..5000ms")
    if not 0 <= args.exmcu_packet_delay_ms <= 5000:
        parser.error("EX MCU arrival hypothesis must be0..5000ms")
    if not 0 <= args.exmcu_key_delay_ms <= 5000:
        parser.error("GPIO-sampled KEY arrival hypothesis must be0..5000ms")
    if not 0 <= args.exmcu_power_delay_ms <= 5000:
        parser.error("C-initialized power report arrival hypothesis must be0..5000ms")
    if not 0 <= args.exmcu_service0d_delay_ms <= 5000:
        parser.error("Original GPIO reply arrival hypothesis must be0..5000ms")
    if not 0 <= args.exmcu_service0d_command01_delay_ms <= 5000:
        parser.error("Native command01 reply delay must be0..5000ms")
    if args.exmcu_service0d_command01_packet and not args.exmcu_service0d_packet:
        parser.error("Original wire81 replay requires the preceding original wire82 input")
    if args.peer_business_trace_only:
        other_focus = (args.no_observers, args.resource_trace, args.serial_trace,
            args.slave_device_trace, args.power_input_trace, args.policy_trace,
            args.service0d_trace_only, args.policy_followup_only,
            args.policy_group2_source_only, args.controller_prerequisite_only,
            args.controller_context_only, args.controller_notification_only,
            args.orientation_config_only, args.config_notification_only,
            args.config_sync_only, args.sys_config_wire_only, args.gennor_lifecycle_only,
            args.dma_allocation_only, args.policy_group2_watch_only)
        if not args.integrated or args.legacy_single or any(other_focus):
            parser.error("Peer business trace uses only the integrated original dual-guest observer set")
    task_plan = task_plan_identity = None
    if args.task_observation_plan:
        from expeed_task_observer import load_plan
        original_blobs = {role: (ROOT / f"inputs/firmware/{role}-original-with-crc.bin").read_bytes()
                          for role in ("master", "slave")}
        task_plan, task_plan_identity = load_plan(args.task_observation_plan, original_blobs)
    directory = args.output_dir.resolve() if args.output_dir else (
        OUT / (time.strftime("%Y%m%d-%H%M%S") + "-" + args.label))
    directory.mkdir(parents=True, exist_ok=False)
    port = Path(__file__).resolve().parent
    manifest_path = Path(args.qemu_build_manifest or port / "z6ii/build-manifest.json").resolve(strict=True)
    selected_manifest = json.loads(manifest_path.read_text())
    parameter_size, dma_view_offset = peer_parameter_layout(selected_manifest) if args.peer_parameter_section else (None, None)
    peer_parameter = directory / "master-C7F00000-parameter-sections.bin" if args.peer_parameter_section else None
    if peer_parameter:
        with peer_parameter.open("xb") as stream:
            stream.truncate(parameter_size)
    backing = directory / "two-ended-queues.bin"
    peer_buffer = directory / "master-C2900000-peer-section.bin" if args.peer_buffer_section else None
    if peer_buffer:
        with peer_buffer.open("xb") as stream:
            stream.truncate(0x100000)
    peer_data = directory / "master-C2C00000-peer-data-section.bin" if args.peer_data_section else None
    peer_data_size = peer_data_layout(selected_manifest) if peer_data else None
    if peer_data:
        with peer_data.open("xb") as stream:
            stream.truncate(peer_data_size)
    peer_dma = (peer_parameter if dma_view_offset is not None else directory / "master-C8300000-peer-DMA-section.bin") if args.peer_dma_section else None
    if peer_dma and peer_dma != peer_parameter:
        with peer_dma.open("xb") as stream:
            stream.truncate(0x100000)
    slave_dma = directory / "slave-C6B00000-DMA-sections.bin" if args.slave_dma_section else None
    if slave_dma:
        with slave_dma.open("xb") as stream:
            stream.truncate(0x300000)
    if args.lcd_snapshot_interval and not 1 <= args.lcd_snapshot_interval <= 180:
        raise ValueError("LCD snapshot interval must be 0 or 1..180 seconds")
    report = dict(camera_access=False, original_entry="0x10020000",
                  LCD_snapshot_interval_host_seconds=args.lcd_snapshot_interval,
                  LCD_snapshot_timeline=[],
                  bootloader_image_present=False, factory_configuration_present=False,
                  instruction_bytes_modified=False, diagnostic_function_calls=[],
                  guest_RAM_or_register_fixtures=[], menu_verified=False,
                  full_power_on_boot_verified=False, integrated_model=args.integrated,
                  legacy_single_guest_scripted_peer=args.legacy_single,
                  budget_seconds=args.seconds, passive_observers=not args.no_observers,
                  selected_QEMU_build_manifest=str(args.qemu_build_manifest.resolve()) if args.qemu_build_manifest else None,
                  QEMU_exception_trace=args.qemu_exception_trace,
                  phase2_serial_initialization_trace=args.phase2_serial_trace,
                  original_peer_parameter_completion_trace=args.peer_parameter_trace,
                  source50_fallback_trace=args.source50_fault_trace,
                  source50_copy_trace=args.source50_copy_trace,
                  source50_TCG_trace=args.source50_tcg_trace,
                  boot_TCG_trace=args.boot_tcg_trace,
                  conditional_seed_only_observers=args.conditional_seed_only_observers,
                  zero_observer_execution=False if args.conditional_seed_only_observers else args.no_observers,
                  original_GPIO_route_trace=args.gpio_route_trace,
                  native_MCU_wire_path=str(args.mcu_wire_path.resolve()) if args.mcu_wire_path else None,
                  native_MCU_wire_poll_ns_hypothesis=args.mcu_wire_poll_ns,
                  native_MCU_wire_known_wait_ms_hypothesis=args.mcu_wire_known_wait_ms,
                  native_MCU_wire_host_causality_experiment=bool(args.mcu_wire_known_wait_ms),
                  native_MCU_wire_physical_latency_verified=False,
                  native_MCU_wire_clocks_synchronized=False,
                  workspace_source_snapshot_is_selected_binary_identity=False,
                  TG_event_test_mode=args.tg_event_test,
                  TG_event_test_physical_sensor_model=False,
                  resource_trace=args.resource_trace,
                  serial_trace=args.serial_trace,
                  slave_device_trace=args.slave_device_trace,
                  peer_business_trace_only=args.peer_business_trace_only,
                  display_configuration_timing_trace=args.display_config_trace,
                  slave_2B200300_control_latch_reset0_hypothesis=args.slave_2b20_control_latch,
                  slave_2B200300_physical_semantics_verified=False,
                  slave_pipeline_mode_hypothesis=args.slave_pipeline_mode,
                  slave_pipeline_physical_semantics_verified=False,
                  shared_event_poll_ns_hypothesis=args.shared_event_poll_ns,
                  slave_access_ready_line_hypothesis=args.slave_access_ready_line,
                  slave_SDHCI_mode_hypothesis=args.slave_sdhci_mode,
                  slave_SDHCI_physical_semantics_verified=False,
                  slave_virtual_filesystem=args.slave_filesystem if args.slave_sdhci_mode == "fat-card" else None,
                  power_input_trace=args.power_input_trace,
                  policy_trace=args.policy_trace,
                  service0D_trace_only=args.service0d_trace_only,
                  policy_followup_trace_only=args.policy_followup_only,
                  policy_group2_source_trace_only=args.policy_group2_source_only,
                  controller_prerequisite_trace_only=args.controller_prerequisite_only,
                  controller_context_trace_only=args.controller_context_only,
                  controller_notification_trace_only=args.controller_notification_only,
                  orientation_configuration_trace_only=args.orientation_config_only,
                  configuration_notification_trace_only=args.config_notification_only,
                  configuration_sync_trace_only=args.config_sync_only,
                  SYS_configuration_wire_trace_only=args.sys_config_wire_only,
                  GENNOR_lifecycle_trace_only=args.gennor_lifecycle_only,
                  DMA_allocation_trace_only=args.dma_allocation_only,
                  policy_group2_write_watchpoint=args.policy_group2_watch_only,
                  icount_shift_hypothesis=args.icount_shift,
                  instruction_timing_physically_verified=False,
                  EX_MCU_full_firmware_executed=False,
                  EX_MCU_input_transport_emulated=args.exmcu_transport,
                  EX_MCU_input_packet=str(args.exmcu_packet.resolve()) if args.exmcu_packet else None,
                  EX_MCU_packet_is_original_serializer_diagnostic_replay=bool(args.exmcu_packet),
                  EX_MCU_packet_arrival_delay_ms_hypothesis=args.exmcu_packet_delay_ms,
                  EX_MCU_SYS_version_packet=str(args.exmcu_sys_version_packet.resolve()) if args.exmcu_sys_version_packet else None,
                  EX_MCU_SYS_C_initialized_packet=str(args.exmcu_sys_state_packet.resolve()) if args.exmcu_sys_state_packet else None,
                  EX_MCU_SYS_response_delay_ms_hypothesis=args.exmcu_sys_delay_ms,
                  EX_MCU_SYS_state_after_version_delay_ms_hypothesis=100 if args.exmcu_sys_state_packet else None,
                  EX_MCU_SYS_physical_state_sampling_executed=False,
                  EX_MCU_GPIO_sampled_KEY_packet=str(args.exmcu_key_packet.resolve()) if args.exmcu_key_packet else None,
                  EX_MCU_KEY_arrival_delay_ms_hypothesis=args.exmcu_key_delay_ms,
                  EX_MCU_KEY_physical_pin_levels_measured=False,
                  EX_MCU_C_initialized_power_packet=str(args.exmcu_power_packet.resolve()) if args.exmcu_power_packet else None,
                  EX_MCU_power_arrival_delay_ms_hypothesis=args.exmcu_power_delay_ms,
                  EX_MCU_power_physical_sampling_executed=False,
                  EX_MCU_service0D_native_GPIO_reply=str(args.exmcu_service0d_packet.resolve()) if args.exmcu_service0d_packet else None,
                  EX_MCU_service0D_reply_delay_ms_hypothesis=args.exmcu_service0d_delay_ms,
                  EX_MCU_service0D_reply_only_exact_sequence1=True if args.exmcu_service0d_packet else None,
                  EX_MCU_service0D_physical_GPIO_effect_verified=False,
                  EX_MCU_service0D_original_lock_error_retained=True if args.exmcu_service0d_packet else None,
                  EX_MCU_service0D_command01_packet=str(args.exmcu_service0d_command01_packet.resolve()) if args.exmcu_service0d_command01_packet else None,
                  EX_MCU_service0D_command01_reply_delay_ms_hypothesis=args.exmcu_service0d_command01_delay_ms,
                  EX_MCU_service0D_command01_only_exact_sequence2=True if args.exmcu_service0d_command01_packet else None,
                  EX_MCU_service0D_command01_MCU_init_phase1_is_diagnostic=True,
                  EX_MCU_service0D_command01_phase_natural_caller_verified=False,
                  observed_peer_buffer_section=str(peer_buffer) if peer_buffer else None,
                  observed_peer_data_section=str(peer_data) if peer_data else None,
                  peer_data_backing_bytes=peer_data_size,
                  observed_peer_DMA_section=str(peer_dma) if peer_dma else None,
                  observed_slave_DMA_section=str(slave_dma) if slave_dma else None,
                  observed_peer_parameter_section=str(peer_parameter) if peer_parameter else None,
                  peer_parameter_pool_bytes=parameter_size,
                  peer_DMA_shared_pool_offset=dma_view_offset if peer_parameter else None,
                  peer_parameter_sections_are_host_payload_fixtures=diagnostic_body is not None,
                  parameter_require_recorded_body=args.parameter_require_recorded_body,
                  parameter_source_read_only_reference=parameter_reference,
                  diagnostic_region47_RAM_seed_requested=diagnostic_body is not None,
                  region47_original_Flash_loader_generation_verified=False,
                  peer_parameter_physical_mapping_verified=False,
                  peer_parameter_copy_timing_physically_verified=False,
                  peer_parameter_copy_ns_per_byte_hypothesis=10 if peer_parameter else None,
                  peer_parameter_stop_status2_supplied=False,
                  slave_fill_channel1_hypothesis=args.slave_fill_channel1,
                  master_fill_channel1_hypothesis=args.master_fill_channel1,
                  peer_buffer_physical_mapping_verified=False,
                  passive_stop_at=hex(args.stop_at) if args.stop_at else None,
                  engines={}, observations=[])
    if args.expeed_byte_ledger:
        report["EXPEED_debugger_byte_ledgers_requested"] = True
    if args.stop_both_before_snapshot:
        report["two_EXPEED_stop_before_final_observation_requested"] = True
    if task_plan is not None:
        plan_saved = directory / "任务观察计划.json"
        plan_saved.write_bytes(Path(task_plan_identity["path"]).read_bytes())
        assert hashlib.sha256(plan_saved.read_bytes()).hexdigest() == task_plan_identity["sha256"]
        report["task_observation_plan_input"] = task_plan_identity
        report["task_observation_plan_saved"] = str(plan_saved)
    # Keep the exact harness and model source used for this run. Previous
    # runs that predate this field do not have a locked harness source hash.
    source_directory = directory / "harness-sources"
    source_directory.mkdir(exist_ok=False)
    report["harness_source_snapshot"] = []
    source_relatives = ["natural_boot.py", "probe_z6ii.py", "run_evidence.py", "coupled_dual.py",
                     "application_z6ii.py", "guest_call.py", "dual_menu_session.py",
                     "menu_ocr.py", "review_original_dual_menu.py",
                     "run_original_dual_stage.py", "host_env.py", "virtual_sd.py", "z6ii/build-manifest.json",
                     "z6ii/nikon-z6ii.c", "z6ii/nikon-z6ii-slave-pipeline.h",
                     "z6ii/nikon-z6ii-slave-storage.h", "z6ii/nikon-z6ii.Kconfig", "build_z6ii.py",
                     "z6ii/nikon-z6ii-exmcu.h", "z6ii/nikon-z6ii-devices.h",
                     "z6ii/nikon-z6ii-wire.h", "z6ii/mcu_wire_posix.h", "z6ii/mcu_wire_bus.h",
                     "z6ii/nikon-z6ii-coupled-link.h",
                     "generate_devices.py", "generate_z6ii_profile.py", "persistent_input.py", "recorded_ram_input.py"]
    if args.initial_resource_startup_barrier:
        source_relatives.append('startup_barrier.py')
    if loader_runtime_reference is not None:
        source_relatives.append('loader_runtime_audit.py')
    if args.expeed_byte_ledger or args.stop_both_before_snapshot:
        source_relatives.extend(("debugger_byte_ledger.py", "expeed_task_observer.py",
                                 "tools/rsp.py", "tools/interactive.py"))
    if "nikon-z6ii-peer-parameter.h" in selected_manifest.get("immutable_model_sources", {}):
        source_relatives.append("z6ii/nikon-z6ii-peer-parameter.h")
    for relative in source_relatives:
        source_path = port / relative
        source_basis = "current_host_harness"
        expected_digest = None
        if relative == "z6ii/build-manifest.json":
            source_path, source_basis = manifest_path, "selected_build_manifest"
        elif relative.startswith("z6ii/"):
            name = Path(relative).name
            immutable = selected_manifest.get("immutable_model_sources", {}).get(name)
            if name == "nikon-z6ii.Kconfig":
                immutable = selected_manifest.get("Kconfig_overlay_snapshot")
            if immutable:
                source_path, source_basis = Path(immutable), "immutable_selected_build_model_snapshot"
                expected_digest = selected_manifest.get("z6ii_sources", {}).get(name)
            else:
                source_basis = "current_model_source_not_build_pinned"
        elif relative in selected_manifest.get("model_generator_sources", {}):
            entry = selected_manifest["model_generator_sources"][relative]
            source_path, source_basis = Path(entry["snapshot"]), "immutable_selected_build_generator_snapshot"
            expected_digest = entry["sha256"]
        data = source_path.read_bytes()
        if expected_digest:
            assert hashlib.sha256(data).hexdigest() == expected_digest, relative
        target = source_directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        report["harness_source_snapshot"].append(dict(source=str(source_path),
            saved=str(target), source_basis=source_basis,
            bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    report["shared_backing"] = create_backing(backing, notifications=True, gpio=True,
                                            wire=True, phy=True, stop=True, lanes=True)
    engines, enabled, counts = {}, {}, {}
    observers = {role: dict(items) for role, items in OBSERVERS.items()}
    if args.peer_business_trace_only:
        observers = {role: dict(items) for role, items in PEER_BUSINESS_OBSERVERS.items()}
    if args.phase2_serial_trace:
        observers["master"].update(PHASE2_SERIAL_OBSERVERS)
    if args.peer_parameter_trace:
        if args.no_observers:
            raise ValueError("Parameter-copy tracing requires passive observers")
        observers["slave"].update(PEER_PARAMETER_OBSERVERS)
    if args.source50_fault_trace:
        observers["master"].update(SOURCE50_FAULT_OBSERVERS)
    if args.source50_copy_trace:
        observers["master"].update(SOURCE50_COPY_OBSERVERS)
    if args.gpio_route_trace:
        observers["master"].update(GPIO_ROUTE_OBSERVERS)
    if args.resource_trace:
        observers["master"].update(RESOURCE_OBSERVERS)
    if args.serial_trace:
        observers["master"].update(SERIAL_OBSERVERS)
    if args.slave_device_trace:
        observers["slave"].update(SLAVE_DEVICE_OBSERVERS)
    if args.power_input_trace:
        observers["master"].update(POWER_INPUT_OBSERVERS)
    if args.policy_trace:
        observers["master"].update(POLICY_OBSERVERS)
    if args.service0d_trace_only:
        observers = {"master": {address: POLICY_OBSERVERS[address] for address in
            (0x10386960, 0x10386B7C, 0x10386AFE, 0x1030F1E2, 0x1030F9DC,
             0x1038654C, 0x10386614)},
            "slave": {}}
    if args.policy_followup_only:
        if (args.service0d_trace_only or args.policy_group2_source_only or
                args.controller_prerequisite_only):
            raise ValueError("Select one focused observer set")
        observers = {"master": dict(POLICY_FOLLOWUP_OBSERVERS), "slave": {}}
    if args.policy_group2_source_only:
        if args.service0d_trace_only or args.no_observers or args.controller_prerequisite_only:
            raise ValueError("Select one focused observer set")
        observers = {"master": dict(POLICY_GROUP2_SOURCE_OBSERVERS), "slave": {}}
    if args.controller_prerequisite_only:
        if args.service0d_trace_only or args.no_observers:
            raise ValueError("Select one focused observer set")
        observers = {"master": dict(CONTROLLER_PREREQUISITE_OBSERVERS), "slave": {}}
    if args.policy_group2_watch_only:
        if (args.no_observers or args.policy_followup_only or args.service0d_trace_only or
                args.policy_group2_source_only or args.controller_prerequisite_only):
            raise ValueError("Select the group2 watchpoint alone")
        observers = {"master": {}, "slave": {}}
    if args.controller_context_only:
        if (args.no_observers or args.policy_followup_only or args.service0d_trace_only or
                args.policy_group2_source_only or args.controller_prerequisite_only or
                args.policy_group2_watch_only):
            raise ValueError("Select one focused observer set")
        observers = {"master": dict(CONTROLLER_CONTEXT_OBSERVERS), "slave": {}}
    if args.controller_notification_only:
        if (args.no_observers or args.policy_followup_only or args.service0d_trace_only or
                args.policy_group2_source_only or args.controller_prerequisite_only or
                args.policy_group2_watch_only or args.controller_context_only):
            raise ValueError("Select one focused observer set")
        observers = {"master": dict(CONTROLLER_NOTIFICATION_OBSERVERS), "slave": {}}
    if args.orientation_config_only:
        if (args.no_observers or args.policy_followup_only or args.service0d_trace_only or
                args.policy_group2_source_only or args.controller_prerequisite_only or
                args.policy_group2_watch_only or args.controller_context_only or
                args.controller_notification_only):
            raise ValueError("Select one focused observer set")
        observers = {"master": dict(ORIENTATION_CONFIG_OBSERVERS), "slave": {}}
    if args.config_notification_only:
        if (args.no_observers or args.policy_followup_only or args.service0d_trace_only or
                args.policy_group2_source_only or args.controller_prerequisite_only or
                args.policy_group2_watch_only or args.controller_context_only or
                args.controller_notification_only or args.orientation_config_only):
            raise ValueError("Select one focused observer set")
        observers = {"master": dict(CONFIG_NOTIFICATION_OBSERVERS), "slave": {}}
    if args.config_sync_only:
        if (args.no_observers or args.policy_followup_only or args.service0d_trace_only or
                args.policy_group2_source_only or args.controller_prerequisite_only or
                args.policy_group2_watch_only or args.controller_context_only or
                args.controller_notification_only or args.orientation_config_only or
                args.config_notification_only):
            raise ValueError("Select one focused observer set")
        observers = {"master": dict(CONFIG_SYNC_OBSERVERS), "slave": {}}
    if args.sys_config_wire_only:
        if (args.no_observers or args.policy_followup_only or args.service0d_trace_only or
                args.policy_group2_source_only or args.controller_prerequisite_only or
                args.policy_group2_watch_only or args.controller_context_only or
                args.controller_notification_only or args.orientation_config_only or
                args.config_notification_only or args.config_sync_only):
            raise ValueError("Select one focused observer set")
        observers = {"master": dict(SYS_CONFIG_WIRE_OBSERVERS), "slave": {}}
    if args.gennor_lifecycle_only:
        if (args.no_observers or args.policy_followup_only or args.service0d_trace_only or
                args.policy_group2_source_only or args.controller_prerequisite_only or
                args.policy_group2_watch_only or args.controller_context_only or
                args.controller_notification_only or args.orientation_config_only or
                args.config_notification_only or args.config_sync_only or args.sys_config_wire_only):
            raise ValueError("Select one focused observer set")
        observers = {"master": dict(GENNOR_LIFECYCLE_OBSERVERS), "slave": {}}
    if args.dma_allocation_only:
        focused = (args.no_observers, args.gennor_lifecycle_only,
            args.sys_config_wire_only, args.config_sync_only, args.config_notification_only,
            args.orientation_config_only, args.controller_notification_only,
            args.controller_context_only, args.controller_prerequisite_only,
            args.policy_group2_watch_only, args.policy_group2_source_only,
            args.policy_followup_only, args.service0d_trace_only,
            args.resource_trace, args.serial_trace, args.slave_device_trace,
            args.power_input_trace, args.policy_trace)
        if any(focused):
            raise ValueError("Select the DMA allocation observer set alone")
        observers = {"master": dict(DMA_ALLOCATION_OBSERVERS), "slave": {}}
    if args.display_config_trace:
        if args.no_observers:
            raise ValueError("Display configuration tracing requires passive observers")
        observers["master"].update(DISPLAY_CONFIG_OBSERVERS)
    if args.conditional_seed_only_observers:
        observers = {"master": {}, "slave": {0x1006AB9C: "conditional real RAM seed at original DMA submission"}}
        report["suppressed_requested_GDB_observers"] = True
        report["retained_GDB_sites"] = {"master": [], "slave": ["0x1006ab9c"]}
    if recorded_ram_checked is not None:
        from recorded_ram_input import HOOK
        observers['master'][HOOK] = 'recorded camera resources at original common runtime entry'
        report['diagnostic_master_resource_RAM_input'] = recorded_ram_checked
        report['diagnostic_master_resource_RAM_replay_performed'] = False
    if args.ipu_resource_origin_trace:
        observers['master'].update(IPUBF_ORIGIN_OBSERVERS)
        report['IPUBF_origin_observation_sites'] = {hex(k): v for k, v in IPUBF_ORIGIN_OBSERVERS.items()}
    start = time.monotonic()
    try:
        for role in (("master",) if args.legacy_single else ("master", "slave")):
            if args.legacy_single:
                p = Probe(role, args.label, assisted=True, link_test_peer=True,
                          graphics_capture=args.graphics_capture, icount_shift=args.icount_shift,
                          build_manifest=args.qemu_build_manifest, qemu_exception_trace=args.qemu_exception_trace,
                          debugger_byte_ledger=args.expeed_byte_ledger,
                          output_directory=directory / "engines" / role if args.expeed_byte_ledger else None)
            else:
                p = Probe(role, args.label, shared_queue=backing, coupled_notifications=True,
                          automatic_peer_irq=True, link_configuration=True, coupled_gpio=True,
                          gpio_connection=True, coupled_phy=True, coupled_stop=True,
                          coupled_lanes=True, natural_boot_board=args.integrated,
                          graphics_capture=args.graphics_capture and args.integrated and role == "master",
                          icount_shift=args.icount_shift, peer_buffer_section=peer_buffer,
                          peer_data_section=peer_data,
                          peer_dma_section=peer_dma, slave_dma_section=slave_dma,
                          peer_parameter_section=peer_parameter,
                          parameter_require_recorded_body=args.parameter_require_recorded_body,
                          parameter_source_reference_spec=args.parameter_source_reference_spec,
                          slave_fill_channel1=args.slave_fill_channel1 and role == "slave",
                          master_fill_channel1=args.master_fill_channel1 and role == "master",
                          exmcu_transport=args.exmcu_transport and role == "master",
                          exmcu_packet=args.exmcu_packet if role == "master" else None,
                          exmcu_packet_delay_ms=args.exmcu_packet_delay_ms if role == "master" else 0,
                          exmcu_sys_version_packet=args.exmcu_sys_version_packet if role == "master" else None,
                          exmcu_sys_state_packet=args.exmcu_sys_state_packet if role == "master" else None,
                          exmcu_sys_delay_ms=args.exmcu_sys_delay_ms if role == "master" else 1000,
                          exmcu_key_packet=args.exmcu_key_packet if role == "master" else None,
                          exmcu_key_delay_ms=args.exmcu_key_delay_ms,
                          exmcu_power_packet=args.exmcu_power_packet if role == "master" else None,
                          exmcu_power_delay_ms=args.exmcu_power_delay_ms,
                          exmcu_service0d_packet=args.exmcu_service0d_packet if role == "master" else None,
                          exmcu_service0d_delay_ms=args.exmcu_service0d_delay_ms,
                          exmcu_service0d_command01_packet=args.exmcu_service0d_command01_packet if role == "master" else None,
                          exmcu_service0d_command01_delay_ms=args.exmcu_service0d_command01_delay_ms,
                          slave_2b20_control_latch=args.slave_2b20_control_latch and role == "slave",
                          slave_pipeline_mode=args.slave_pipeline_mode if role == "slave" else None,
                          shared_event_poll_ns=args.shared_event_poll_ns,
                          slave_access_ready_line=args.slave_access_ready_line and role == "slave",
                          slave_sdhci_mode=args.slave_sdhci_mode if role == "slave" else None,
                          slave_filesystem=args.slave_filesystem if role == "slave" else "FAT16",
                          slave_card_capacity_mib=args.slave_card_capacity_mib if role == "slave" else 256,
                          persistent_input_spec=args.master_persistent_input if role == "master" else args.slave_persistent_input,
                          build_manifest=args.qemu_build_manifest, qemu_exception_trace=args.qemu_exception_trace,
                          mcu_wire_path=args.mcu_wire_path if role == "master" else None,
                          mcu_wire_poll_ns=args.mcu_wire_poll_ns if role == "master" else None,
                          mcu_wire_known_wait_ms=args.mcu_wire_known_wait_ms if role == "master" else None,
                          source50_tcg_trace=args.source50_tcg_trace and role == "master",
                          boot_tcg_trace=args.boot_tcg_trace and role == "master",
                          debugger_byte_ledger=args.expeed_byte_ledger,
                          output_directory=directory / "engines" / role if args.expeed_byte_ledger else None)
            engines[role] = p
            report["engines"][role] = dict(output=str(p.directory),
                                          original_sha256=hashlib.sha256(p.blob).hexdigest(),
                                          persistent_flash_input=p.persistent_input)
            enabled[role], counts[role] = {}, {}
            if not args.no_observers:
                if not args.conditional_seed_only_observers:
                    observers[role].update(ABORT_OBSERVERS[role])
                if args.stop_at:
                    observers["master"].setdefault(args.stop_at, "requested passive master checkpoint")
                for address, name in observers[role].items():
                    expected = p.blob[address - 0x10020000:address - 0x10020000 + 16]
                    actual = p.remote.memory(address, 16)
                    if actual != expected or len(actual) != 16:
                        raise AssertionError(f"Original observer bytes {role} {address:x}")
                    if p.remote.command(f"Z1,{address:x},2") != "OK":
                        raise RuntimeError("Passive hardware breakpoint rejected")
                    enabled[role][address] = name
            if role == "master" and args.policy_group2_watch_only:
                assert p.remote.command("Z2,c1818f08,4") == "OK"
                report["policy_group2_watchpoint"] = dict(address="0xc1818f08", bytes=4,
                    access="write", passive=True, guest_memory_written=False,
                    maximum_hits=16, hits=0)
        start = time.monotonic()
        next_lcd_snapshot = args.lcd_snapshot_interval
        retained_lcd_frames = {}
        startup_pending = bool(args.initial_resource_startup_barrier)
        if startup_pending:
            from startup_barrier import ready as barrier_ready, wait_release, check_wait
            slave = engines['slave']
            report['initial_resource_startup_slave_ready'] = barrier_ready(
                args.initial_resource_startup_barrier, 'slave', slave.monitor.command('query-status'),
                slave.process.pid, dict(initial_continue_not_issued=True))
            report['initial_resource_startup_scope'] = 'initial diagnostic RAM replay only; runtime clocks remain separate'
        for role, p in engines.items():
            if startup_pending and role == 'slave':
                continue
            p.remote.send("c")
            p.running = True
        while startup_pending or time.monotonic() - start < args.seconds:
            if startup_pending:
                check_wait(args.initial_resource_startup_barrier,
                           [p.process for p in engines.values()])
            elapsed = time.monotonic() - start
            master = engines.get("master")
            if (not startup_pending and args.lcd_snapshot_interval and elapsed >= next_lcd_snapshot and
                    master is not None and master.process.poll() is None):
                from PIL import Image
                capture = master.directory / "LCD-timeline"
                capture.mkdir(exist_ok=True)
                path = capture / f"frame{len(report['LCD_snapshot_timeline']) + 1:03d}.ppm"
                master.monitor.command("screendump", {"filename": str(path)})
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                previous = retained_lcd_frames.get(digest)
                if previous is None:
                    with Image.open(path) as image:
                        image.save(path.with_suffix(".png"))
                        size = list(image.size)
                    frame = dict(png=str(path.with_suffix(".png")), ppm=str(path), size=size,
                        ppm_sha256=digest,
                        png_sha256=hashlib.sha256(path.with_suffix(".png").read_bytes()).hexdigest())
                    retained_lcd_frames[digest] = dict(frame=frame,
                        sample=len(report['LCD_snapshot_timeline']) + 1)
                    duplicate_of_sample = None
                else:
                    # Only the just-created duplicate is removed. Every sample
                    # retains its time and the exact existing frame identity.
                    path.unlink()
                    frame = previous["frame"]
                    duplicate_of_sample = previous["sample"]
                report["LCD_snapshot_timeline"].append(dict(**frame,
                    host_seconds=round(elapsed, 6), duplicate_of_sample=duplicate_of_sample,
                    capture_request_path=str(path),
                    guest_stopped=False, guest_input_supplied=False))
                # One small live index lets external pad input follow the
                # current native GUI even when the pixels reuse an old frame.
                current = capture / "current.json"
                temporary = current.with_suffix(".tmp")
                temporary.write_text(json.dumps(report["LCD_snapshot_timeline"][-1], indent=2) + "\n")
                temporary.replace(current)
                next_lcd_snapshot = time.monotonic() - start + args.lcd_snapshot_interval
            active = {p.remote.sock: role for role, p in engines.items()
                      if p.process.poll() is None and p.running}
            if not active:
                break
            ready, _, _ = select.select(list(active), [], [], 0.05)
            for sock in ready:
                # A continue command first produces a bare RSP '+' ACK. It is
                # not a stop. Buffer available bytes without waiting for a
                # packet while the other guest is running.
                role = active[sock]
                p = engines[role]
                try:
                    data = sock.recv(65536)
                    if not data:
                        p.running = False
                        report["engines"][role]["remote_eof"] = True
                        continue
                    p.remote.buffer.extend(data)
                except (ConnectionError, OSError) as error:
                    p.running = False
                    report["engines"][role]["transport_error"] = str(error)
            for role, p in engines.items():
                if not p.running:
                    continue
                buffer = p.remote.buffer
                start_packet = buffer.find(b"$")
                end_packet = buffer.find(b"#", start_packet + 1) if start_packet >= 0 else -1
                if end_packet < 0 or len(buffer) < end_packet + 3:
                    continue
                try:
                    reply = p.remote.receive()
                except (EOFError, ConnectionError, OSError) as error:
                    p.running = False
                    report["engines"][role]["transport_error"] = str(error)
                    continue
                p.running = False
                if "thread:" not in reply:
                    report["engines"][role]["exit_reply"] = reply
                    continue
                thread = reply.split("thread:")[1].split(";")[0]
                # An unknown device access can terminate this guest just
                # after a queued breakpoint reply. Preserve that boundary
                # and continue collecting the surviving guest; a stale RSP
                # reply is not a firmware exception in the other engine.
                try:
                    p.remote.command("Hg" + thread)
                    regs = p.remote.registers()
                except (EOFError, ConnectionError, OSError) as error:
                    report["engines"][role]["transport_error"] = str(error)
                    continue
                address = int(regs["r15"], 16)
                name = enabled[role].get(address)
                watch_stop = (role == "master" and args.policy_group2_watch_only and
                              "watch:c1818f08;" in reply.lower())
                if watch_stop:
                    name = "native policy group2 write watchpoint"
                if name is None:
                    p.snapshot("unexpected passive stop", reply)
                    report["engines"][role]["unexpected_stop"] = regs
                    continue
                counts[role][address] = counts[role].get(address, 0) + 1
                record = dict(role=role, thread=thread, name=name, address=hex(address),
                              seconds=round(time.monotonic() - start, 4), registers=regs)
                report["observations"].append(record)
                if role == 'master' and recorded_ram_checked is not None and address == HOOK:
                    from recorded_ram_input import replay
                    if report['diagnostic_master_resource_RAM_replay_performed']:
                        raise ValueError('Recorded Master resource RAM replay must occur once only')
                    replay_started = time.monotonic()
                    fixture = replay(p.remote, p.blob, recorded_ram_bodies)
                    report['resource_RAM_replay_host_seconds'] = round(time.monotonic() - replay_started, 6)
                    fixture['input_spec'] = recorded_ram_checked['spec']
                    record.update(observation_only=False, diagnostic_master_resource_RAM_replay=fixture)
                    report['guest_RAM_or_register_fixtures'].append(fixture)
                    report['diagnostic_master_resource_RAM_replay_performed'] = True
                    replay_path = directory / 'recorded-master-resource-RAM-replay.json'
                    replay_path.write_text(json.dumps(fixture, ensure_ascii=False, indent=2) + '\n')
                    if startup_pending:
                        report['initial_resource_startup_master_ready'] = barrier_ready(
                            args.initial_resource_startup_barrier, 'master', p.monitor.command('query-status'),
                            p.process.pid, dict(resource_readback_equal=all(x['readback_equal'] for x in fixture['regions']),
                                original_CPU_state_unchanged=fixture['original_CPU_state_unchanged'],
                                original_common_runtime_entry_verified=fixture['original_common_Thumb_runtime_entry_verified']))
                        report['initial_resource_startup_release'] = wait_release(
                            args.initial_resource_startup_barrier, [engine.process for engine in engines.values()])
                        report['initial_resource_QMP_status_before_continue'] = {}
                        for held_role, engine in engines.items():
                            status = engine.monitor.command('query-status')
                            if status.get('running') is not False:
                                raise ValueError(held_role + ' must remain stopped until initial resource release')
                            report['initial_resource_QMP_status_before_continue'][held_role] = status
                        start = time.monotonic()
                        record['seconds_before_initial_resource_release'] = record['seconds']
                        record['seconds'] = 0
                        next_lcd_snapshot = args.lcd_snapshot_interval
                        startup_pending = False
                        slave = engines['slave']
                        slave.remote.send('c')
                        slave.running = True
                if role == "slave" and address in PEER_PARAMETER_OBSERVERS:
                    raw_code = p.remote.memory(address, 16)
                    assert raw_code == p.blob[address - 0x10020000:address - 0x10020000 + 16]
                    record.update(observation_only=True,
                        extra_MMIO_read_issued=False,
                        original_instruction_bytes=raw_code.hex())
                    if address == 0x1006AA40:
                        record["original_status_read_and_acknowledged"] = regs["r0"]
                    if address == 0x1006AA76:
                        record.update(original_BX_r2_callback_target=regs["r2"],
                            original_callback_event=regs["r0"],
                            original_callback_record_address=regs["r1"])
                    if address == 0x100694E6:
                        pointer = int(regs["r1"], 16)
                        if 0xC0000000 <= pointer <= 0xD0000000 - 0x24:
                            record.update(original_callback_event=regs["r0"],
                                original_callback_record_address=hex(pointer),
                                original_callback_record_bytes=p.remote.memory(pointer, 0x24).hex())
                        descriptor = report["engines"][role].get("last_original_fill_descriptor", {})
                        shape = descriptor.get("original_fill_descriptor")
                        if diagnostic_body is not None and shape == '0001000040004000400000360080064840802ac700000000000000000000000011000000':
                            data = p.remote.memory(0xc72a8040, 0xd8000)
                            target = p.directory / 'diagnostic-region47-DMA-destination.bin'
                            target.write_bytes(data)
                            before = descriptor['diagnostic_region47_RAM_seed']['destination_neighbors_before']
                            after = {'before': p.remote.memory(0xc72a8040 - 256, 256).hex(),
                                     'after': p.remote.memory(0xc7380040, 256).hex()}
                            record['diagnostic_region47_DMA_verification'] = dict(
                                destination='0xc72a8040', bytes=len(data), path=str(target),
                                sha256=hashlib.sha256(data).hexdigest(), bytes_equal_recorded_body=data == diagnostic_body,
                                destination_neighbors_after=after, destination_neighbors_unchanged=before == after,
                                paused_read_only_capture=True, source_loader_generation_omitted=True,
                                full_natural_boot_verified=False)
                        if shape == "00010000600060006000003c0000f047000010c700000000000000000000000011000000":
                            # Read actual completed slave RAM while its original callback
                            # is paused. Do not read or supply any device register/state.
                            data = p.remote.memory(0xC7100000, 0x168000)
                            target = p.directory / f"original-parameter-copy-destination-{counts[role][address]}.bin"
                            target.write_bytes(data)
                            record["original_callback_destination_capture"] = dict(
                                address="0xc7100000", bytes=len(data), path=str(target),
                                sha256=hashlib.sha256(data).hexdigest(),
                                paused_read_only=True, guest_RAM_written=False,
                                extra_MMIO_read_issued=False)
                    if address in (0x10069500, 0x10069504):
                        record["original_eventflag_call_argument_or_return"] = regs["r0"]
                        record["original_eventflag_mask_register"] = regs["r1"]
                    if address == 0x10069552:
                        record["original_wait_return_r0"] = regs["r0"]
                if role == "master" and address in SOURCE50_COPY_OBSERVERS:
                    channel = int(regs["r4" if address == 0x103A5F88 else "r0"], 16)
                    record.update(fallback_callback_slot_bytes=p.remote.memory(0xC1864CE8, 4).hex(),
                        region50_notification_bytes=p.remote.memory(0xC20A4248, 0x30).hex(),
                        DMA_state_table_address="0xc180946c",
                        DMA_state_table_prefix_bytes=p.remote.memory(0xC180946C, 0xA0).hex(),
                        observation_only=True,
                        original_instruction_bytes=p.remote.memory(address, 16).hex())
                    assert bytes.fromhex(record["original_instruction_bytes"]) == p.blob[
                        address - 0x10020000:address - 0x10020000 + 16]
                    if address != 0x103C2CCE:
                        record["original_DMA_channel_argument"] = channel
                        if channel < 32:
                            state_address = 0xC180946C + channel * 0x14
                            state = p.remote.memory(state_address, 0x14)
                            record.update(original_DMA_state_address=hex(state_address),
                                original_DMA_state_bytes=state.hex(),
                                original_DMA_ownership_byte5=state[5])
                    if address == 0x103A5F88:
                        record["original_DMA_ownership_predicate_return"] = int(regs["r0"], 16)
                    if address == 0x103C2CCE:
                        record["original_copy_helper_return"] = int(regs["r0"], 16)
                        item_pointer = int(regs["r9"], 16)
                        if 0x10020000 <= item_pointer <= 0x10020000 + len(p.blob) - 16:
                            record.update(original_source_item_address=hex(item_pointer),
                                original_source_item_bytes=p.remote.memory(item_pointer, 16).hex())
                if role == "master" and address in GPIO_ROUTE_OBSERVERS:
                    record.update(observation_only=True,
                        extra_GPIO_MMIO_read_issued=False,
                        original_instruction_bytes=p.remote.memory(address, 16).hex())
                    assert bytes.fromhex(record["original_instruction_bytes"]) == p.blob[
                        address - 0x10020000:address - 0x10020000 + 16]
                    if address in (0x1036AC1A, 0x1036AC1E, 0x1036AC22):
                        root = p.remote.memory(0xC1800008, 4)
                        mapping_pointer = int.from_bytes(root, "little")
                        record.update(original_GPIO_mapping_root_address="0xc1800008",
                            original_GPIO_mapping_root_bytes=root.hex(),
                            original_GPIO_mapping_table_address=hex(mapping_pointer))
                        if address != 0x1036AC22:
                            logical = int(regs["r0"], 16)
                            record["original_GPIO_logical_id"] = logical
                            mapped_address = mapping_pointer + logical * 2
                            if logical < 256 and (0xC0000000 <= mapped_address < 0xD0000000 - 2 or
                                    0x10020000 <= mapped_address < 0x10020000 + len(p.blob) - 2):
                                mapped = p.remote.memory(mapped_address, 2)
                                record.update(original_GPIO_mapping_row_address=hex(mapped_address),
                                    original_GPIO_mapping_row_bytes=mapped.hex(),
                                    original_GPIO_mapped_id_in_table=int.from_bytes(mapped, "little"))
                        else:
                            record["original_GPIO_mapped_id_return"] = int(regs["r0"], 16)
                    if address in (0x10388158, 0x1038817E, 0x10388194, 0x10388188, 0x1038818A):
                        pointer = int(regs["r1" if address in (0x10388188, 0x1038818A) else "r0"], 16)
                        if 0xC0000000 <= pointer < 0xD0000000 - 56:
                            raw = p.remote.memory(pointer, 56)
                            pin_index = raw[4]
                            record.update(original_GPIO_descriptor_address=hex(pointer),
                                original_GPIO_descriptor_bytes=raw.hex(),
                                original_GPIO_descriptor_id=int.from_bytes(raw[:4], "little"),
                                original_GPIO_pin_index=pin_index,
                                original_GPIO_DATA_address=hex(int.from_bytes(raw[8:12], "little")),
                                original_GPIO_consumption_mask=hex(1 << pin_index) if pin_index < 32 else None,
                                original_GPIO_descriptor_plus0C_address=hex(int.from_bytes(raw[12:16], "little")))
                    if address == 0x1038817A:
                        command = int(regs["r2"], 16)
                        record.update(original_GPIO_DATA_write_address=regs["r4"],
                            original_GPIO_masked_write_word=hex(command),
                            original_GPIO_masked_write_enable=hex((command >> 16) & 0xFFFF),
                            original_GPIO_masked_write_level=hex(command & 0xFFFF))
                    if address == 0x1038818A:
                        record["original_GPIO_DATA_raw_return"] = regs["r0"]
                    if address == 0x10388192:
                        record["original_GPIO_one_bit_return"] = int(regs["r0"], 16)
                if role == "master" and address in SOURCE50_FAULT_OBSERVERS:
                    record.update(fallback_callback_object_address="0xc1864cd0",
                        fallback_callback_object_bytes=p.remote.memory(0xC1864CD0, 0x24).hex(),
                        fallback_callback_slot_address="0xc1864ce8",
                        fallback_callback_slot_bytes=p.remote.memory(0xC1864CE8, 4).hex(),
                        upper_gate_words_address="0xc237a788",
                        upper_gate_words_bytes=p.remote.memory(0xC237A788, 8).hex(),
                        region50_notification_address="0xc20a4248",
                        region50_notification_bytes=p.remote.memory(0xC20A4248, 0x30).hex(),
                        region50_descriptor_bytes=p.remote.memory(0xC185F468, 0x18).hex(),
                        phase_announcement_root_address="0xc18a8968",
                        phase_announcement_root_bytes=p.remote.memory(0xC18A8968, 0x10).hex(),
                        counter_48MHz_raw=p.remote.memory(0x04266008, 8).hex(),
                        observation_only=True)
                    original = p.blob[address - 0x10020000:address - 0x10020000 + 16]
                    raw = p.remote.memory(address, 16)
                    assert raw == original
                    record["original_instruction_bytes"] = raw.hex()
                    if address == 0x103CF8EA:
                        record["original_BX_r2_target"] = regs["r2"]
                        record["null_target_observed_before_original_BX"] = int(regs["r2"], 16) == 0
                if role == "master" and address in PHASE2_SERIAL_OBSERVERS:
                    record.update(service6_ops_root=p.remote.memory(0xC1811A74, 4).hex(),
                        service6_serial_binding=p.remote.memory(0xC1811B08, 0x10).hex(),
                        serial_registry_root=p.remote.memory(0xC1887B00, 4).hex(),
                        initialization_observation_is_read_only=True)
                    if address == 0x107638D0:
                        record["original_backend_phase_argument"] = int(regs["r0"], 16)
                    if address == 0x10205698:
                        # Preserve the actual descriptor before original
                        # reserve/submit, rather than infer a wire command
                        # from service ID or the shared completion callback.
                        pointer = int(regs["r1"], 16)
                        if 0xC0000000 <= pointer < 0xD0000000 - 16:
                            descriptor = p.remote.memory(pointer, 16)
                            record["original_submit_descriptor_address"] = hex(pointer)
                            record["original_submit_descriptor_16bytes"] = descriptor.hex()
                            # Original 1020569C/102056B2/102056B8/102056BE
                            # load length/pointer/metadata/command word from
                            # R1. R2 and R3 on entry are not this descriptor.
                            payload = int.from_bytes(descriptor[0:4], "little")
                            length = int.from_bytes(descriptor[4:8], "little")
                            record.update(original_submit_service=int(regs["r0"], 16),
                                original_submit_declared_length=length,
                                original_submit_metadata=descriptor[8],
                                original_submit_command_word=int.from_bytes(descriptor[12:16], "little"),
                                original_submit_payload_address=hex(payload),
                                payload_decode_source="original R1 descriptor loads; not a wire frame")
                            capture_length = min(length, 240)
                            readable = (0xC0000000 <= payload and payload + capture_length <= 0xD0000000 or
                                        0x10020000 <= payload and payload + capture_length <= 0x10020000 + len(p.blob))
                            if readable and capture_length:
                                raw = p.remote.memory(payload, capture_length)
                                record["original_submit_payload_bytes"] = raw.hex()
                                record["original_submit_payload_capture_is_prefix"] = capture_length < length
                                if int(regs["r0"], 16) == 6:
                                    record["service6_payload_command_byte"] = raw[0]
                if role == "master" and address in DISPLAY_CONFIG_OBSERVERS:
                    import struct
                    sp = int(regs["r13"], 16)
                    root = p.remote.memory(0xC1808500, 0x18)
                    holder = struct.unpack_from("<I", root, 4)[0]
                    record.update(counter_48MHz_raw=p.remote.memory(0x04266008, 8).hex(),
                        LCD_configuration_eventflag_object=p.remote.memory(0xC1875330, 4).hex(),
                        LCD_panel_root=root.hex(), LCD_panel_holder_address=hex(holder),
                        stack_address=hex(sp), stack_64bytes=p.remote.memory(sp, 64).hex(),
                        startup_state=p.remote.memory(0xC185E548, 0x24).hex(),
                        LCD_trace_is_read_only=True)
                    if 0xC0000000 <= holder < 0xD0000000 - 0x18:
                        record["LCD_panel_holder"] = p.remote.memory(holder, 0x18).hex()
                    if address == 0x10205226:
                        record.update(LCD_original_wait_result=regs["r0"],
                            LCD_wait_output_flags=p.remote.memory(sp + 0x1C, 4).hex())
                if role == "master" and address == 0x102DE4EC:
                    pointer = int(regs["r1"], 16)
                    if 0xc0000000 <= pointer <= 0xdf000000 - 0x24:
                        record.update(original_fill_descriptor_address=hex(pointer),
                            original_fill_descriptor=p.remote.memory(pointer, 0x24).hex(),
                            original_fill_object=p.remote.memory(int(regs["r0"], 16), 0x14).hex(),
                            original_fill_completion_callback=regs["r2"])
                        report["engines"][role]["last_original_fill_descriptor"] = record
                if role == "master" and address == 0x1038C09A:
                    import struct
                    pointer = int(regs["r1"], 16)
                    record["original_fill_completion_record"] = p.remote.memory(pointer, 0x24).hex()
                    descriptor = report["engines"][role].get("last_original_fill_descriptor", {})
                    if descriptor.get("original_fill_descriptor") and slave_dma:
                        raw = bytes.fromhex(descriptor["original_fill_descriptor"])
                        source_stride, width, destination_stride, rows = struct.unpack_from("<4H", raw, 4)
                        source, destination = struct.unpack_from("<2I", raw, 12)
                        extent = (rows - 1) * destination_stride + width if rows else 0
                        source_extent = (rows - 1) * source_stride + width if rows else 0
                        if (0x46b00000 <= source <= 0x46e00000 - source_extent and
                                0 < extent <= 0x300000 and width <= destination_stride):
                            data = p.remote.memory(destination, extent)
                            transferred = b"".join(data[row*destination_stride:row*destination_stride+width] for row in range(rows))
                            with slave_dma.open("rb") as stream:
                                stream.seek(source - 0x46b00000)
                                source_data = stream.read(source_extent)
                            original = b"".join(source_data[row*source_stride:row*source_stride+width] for row in range(rows))
                            target = p.directory / f"original-reverse-DMA1-destination-{counts[role][address]}.bin"
                            target.write_bytes(data)
                            record["original_DMA1_byte_comparison"] = dict(
                                direction="slave RAM to original master RAM", source_bus=hex(source),
                                slave_RAM=hex(0xc6b00000 + source - 0x46b00000), destination=hex(destination),
                                source_stride=source_stride, width=width, destination_stride=destination_stride, rows=rows,
                                bytes=len(transferred), destination_extent_bytes=extent, destination_path=str(target),
                                destination_sha256=hashlib.sha256(data).hexdigest(),
                                transferred_destination_sha256=hashlib.sha256(transferred).hexdigest(),
                                shared_master_source_sha256=hashlib.sha256(original).hexdigest(),
                                source_role="slave", source_SHA256_field_legacy_name=True,
                                bytes_equal=transferred == original, source_nonzero_bytes=sum(byte != 0 for byte in original),
                                read_only_paused_master_capture=True, physical_bus_mapping_verified=False)
                if role == "slave" and args.peer_business_trace_only:
                    import struct
                    if address == 0x1006AB9C:
                        pointer = int(regs["r1"], 16)
                        if 0xc0000000 <= pointer <= 0xcf000000 - 0x24:
                            record.update(original_fill_descriptor_address=hex(pointer),
                                original_fill_descriptor=p.remote.memory(pointer, 0x24).hex(),
                                original_fill_object=p.remote.memory(int(regs["r0"], 16), 0x14).hex(),
                                original_fill_completion_callback=regs["r2"])
                            report["engines"][role]["last_original_fill_descriptor"] = record
                            if diagnostic_body is not None and record['original_fill_descriptor'] == '0001000040004000400000360080064840802ac700000000000000000000000011000000':
                                if report.get('diagnostic_region47_RAM_seed_performed'):
                                    raise ValueError('Conditional region47 RAM seed must occur once only')
                                before = {'before': p.remote.memory(0xc72a8040 - 256, 256).hex(),
                                          'after': p.remote.memory(0xc7380040, 256).hex()}
                                with peer_parameter.open('r+b', buffering=0) as stream:
                                    stream.seek(0x168000 - 256)
                                    prefix = stream.read(256)
                                    stream.seek(0x240000)
                                    suffix = stream.read(256)
                                    stream.seek(0x168000)
                                    old_body = stream.read(0xd8000)
                                    stream.seek(0x168000)
                                    assert stream.write(diagnostic_body) == len(diagnostic_body)
                                    stream.seek(0x168000)
                                    assert stream.read(0xd8000) == diagnostic_body
                                    stream.seek(0x168000 - 256)
                                    assert stream.read(256) == prefix
                                    stream.seek(0x240000)
                                    assert stream.read(256) == suffix
                                seed = dict(master_RAM='0xc8068000', slave_DMA_bus='0x48068000', backing_offset='0x168000',
                                    bytes=len(diagnostic_body), sha256=hashlib.sha256(diagnostic_body).hexdigest(),
                                    prior_RAM_sha256=hashlib.sha256(old_body).hexdigest(), destination_neighbors_before=before,
                                    source_neighbors_unchanged=True, source_loader_generation_omitted=True,
                                    source_file=str(args.diagnostic_peer_region47_ram.resolve()), original_firmware_instructions_modified=False,
                                    software_ready_or_callback_written=False)
                                record.update(observation_only=False, diagnostic_region47_RAM_seed=seed)
                                report['guest_RAM_or_register_fixtures'].append(seed)
                                report['diagnostic_region47_RAM_seed_performed'] = True
                    if address == 0x100693B6:
                        pointer = int(regs["r1"], 16)
                        record["original_fill_completion_record"] = p.remote.memory(pointer, 0x24).hex()
                        descriptor = report["engines"][role].get("last_original_fill_descriptor", {})
                        if descriptor.get("original_fill_descriptor") and peer_dma:
                            raw = bytes.fromhex(descriptor["original_fill_descriptor"])
                            source, destination = struct.unpack_from("<2I", raw, 12)
                            length = struct.unpack_from("<H", raw, 6)[0]
                            if 0x28300000 <= source <= 0x28400000 - length and 0 < length <= 4096:
                                data = p.remote.memory(destination, length)
                                with peer_dma.open("rb") as stream:
                                    stream.seek(source - 0x28300000 + (dma_view_offset or 0))
                                    original = stream.read(length)
                                target = p.directory / f"original-DMA1-destination-{counts[role][address]}.bin"
                                target.write_bytes(data)
                                record["original_DMA1_byte_comparison"] = dict(
                                    source_bus=hex(source), master_RAM=hex(0xc8300000 + source - 0x28300000),
                                    destination=hex(destination), bytes=length,
                                    destination_path=str(target), destination_sha256=hashlib.sha256(data).hexdigest(),
                                    shared_master_source_sha256=hashlib.sha256(original).hexdigest(),
                                    bytes_equal=data == original, source_nonzero_bytes=sum(byte != 0 for byte in original),
                                    read_only_paused_slave_capture=True, physical_bus_mapping_verified=False)
                    if address == 0x100677E2:
                        length = int(regs["r2"], 16)
                        pointer = int(regs["r3"], 16)
                        if 0 < length <= 256 and 0xc0000000 <= pointer < 0xc6000000 - length:
                            record.update(original_outgoing_payload_address=hex(pointer),
                                original_outgoing_payload=p.remote.memory(pointer, length).hex())
                    if address in (0x1008B3FC, 0x1008B3F6):
                        record["original_pipeline_manager"] = p.remote.memory(0xc1000e98, 0x18).hex()
                    if address in (0x100A5E0C, 0x100A5E10, 0x100B5C26, 0x100B5CFE,
                                   0x100B5C5A, 0x100B5C80, 0x100B5D14):
                        mappings = []
                        for virtual in (0x2a800000, 0x2a810000, 0x2a811000, 0x2a900000):
                            descriptor = int.from_bytes(p.remote.memory(0xc18d4000 + (virtual >> 20) * 4, 4), "little")
                            mappings.append(dict(virtual=hex(virtual), original_L1=hex(descriptor),
                                section_physical=hex((descriptor & 0xfff00000) | (virtual & 0xfffff))
                                    if descriptor & 3 == 2 and not descriptor & (1 << 18) else None))
                        record["original_aperture_page_mappings"] = mappings
                        record["original_upper_initializer_state"] = p.remote.memory(0xc1007b24, 0x30).hex()
                        sp = int(regs["r13"], 16)
                        record["original_upper_initializer_stack"] = p.remote.memory(sp, 64).hex()
                        if address in (0x100B5C5A, 0x100B5C80):
                            record["original_FS_worker_command"] = p.remote.memory(0xc144f688, 0xd0).hex()
                            record["original_FS_mount_arguments"] = p.remote.memory(0xc1007b3c, 8).hex()
                        if address == 0x100A5E10 and args.slave_sdhci_mode:
                            # Fixed original workspace literals100A603E/6044
                            # and100A61E2. Observe DMA output, never modify it.
                            record["original_SD_buffers"] = []
                            for label, addr, length in (("MBR", 0xc6fa1520, 512),
                                                        ("ADMA", 0xc6f9f520, 256)):
                                data = p.remote.memory(addr, length)
                                target = p.directory / f"original-SD-{label}-{counts[role][address]}.bin"
                                target.write_bytes(data)
                                record["original_SD_buffers"].append(dict(label=label,
                                    address=hex(addr), path=str(target), bytes=length,
                                    sha256=hashlib.sha256(data).hexdigest(),
                                    first32_hex=data[:32].hex(), last2_hex=data[-2:].hex()))
                        if address == 0x100A5E0C:
                            target = int(regs["r3"], 16) & ~1
                            if 0x10020000 <= target < 0x10020000 + len(p.blob) - 16:
                                expected = p.blob[target - 0x10020000:target - 0x10020000 + 16]
                                assert p.remote.memory(target, 16) == expected
                                record.update(original_dynamic_initializer=hex(target),
                                    original_dynamic_initializer_bytes=expected.hex())
                    if address in (0x10060F10, 0x10060F16, 0x10060F18, 0x10067768):
                        #10060F10 already loaded the actual callback pointer;
                        #10060F16 dispatches the original264-byte staging record.
                        pointer = int(regs["r8" if address in (0x10060F10, 0x10060F18) else "r0"], 16)
                        if 0xC0000000 <= pointer < 0xD0000000 - 264:
                            data = p.remote.memory(pointer, 264)
                            identifier, kind, seq, length = struct.unpack_from("<IBBH", data)
                            record.update(peer_message_address=hex(pointer),
                                peer_message_id=identifier, peer_message_type=kind,
                                peer_message_sequence=seq, peer_message_length=length,
                                peer_message_raw=data.hex(),
                                peer_message_payload=data[8:8 + min(length,256)].hex())
                        if address in (0x10060F10, 0x10060F16):
                            record.update(actual_callback_pointer=regs["r1"],
                                callback_null=int(regs["r1"],16)==0)
                    if address == 0x100B5D2A:
                        pointer = int(regs["r1"],16)
                        record.update(business_event=regs["r0"],
                            business_message_address=hex(pointer),
                            business_message_raw=p.remote.memory(pointer,264).hex(),
                            type8_local_queue_cursors=p.remote.memory(0xC1487458 + 0x30,8).hex())
                    if address in (0x1008B0F0, 0x1008B252, 0x1008B2B6):
                        sp=int(regs["r13"],16)
                        record.update(original_stack_address=hex(sp),
                            original_stack_256bytes=p.remote.memory(sp,256).hex())
                if role == "master" and address in GENNOR_LIFECYCLE_OBSERVERS:
                    record.update(gennor_lifecycle_snapshot(p.remote))
                if role == "master" and address in DMA_ALLOCATION_OBSERVERS:
                    record.update(dma_allocation_snapshot(p.remote, address, regs))
                if watch_stop:
                    report["policy_group2_watchpoint"]["hits"] += 1
                    record.update(watchpoint_reply=reply, watch_address="0xc1818f08",
                        watched_value_at_stop=p.remote.memory(0xC1818F08, 4).hex(),
                        policy_owner=p.remote.memory(0xC1818BE0, 0x390).hex())
                    window = max(0x10020000, address - 12)
                    if window <= address < 0x10020000 + len(p.blob) - 20:
                        original = p.blob[window - 0x10020000:window - 0x10020000 + 32]
                        assert p.remote.memory(window, 32) == original
                        record.update(original_PC_window_address=hex(window),
                            original_PC_window=original.hex())
                if role == "master" and address in CONFIG_NOTIFICATION_OBSERVERS:
                    sp = int(regs["r13"], 16)
                    record.update(stack_address=hex(sp), stack_64bytes=p.remote.memory(sp, 64).hex(),
                        orientation_configuration_eventflags=p.remote.memory(0xC1875334, 0x30).hex(),
                        region21_descriptor=p.remote.memory(0xC185EDF4, 0x1C).hex(),
                        region57_descriptor=p.remote.memory(0xC185F1E4, 0x1C).hex(),
                        source11_descriptor=p.remote.memory(0xC185E8E8, 0x2C).hex(),
                        source12_descriptor=p.remote.memory(0xC185E914, 0x2C).hex(),
                        region21_notification_record=p.remote.memory(0xC20A3348 + 21 * 0x30, 0x30).hex(),
                        region57_notification_record=p.remote.memory(0xC20A3348 + 57 * 0x30, 0x30).hex(),
                        counter_48MHz_raw=p.remote.memory(0x04266008, 8).hex())
                    if address == 0x1020530C:
                        import struct
                        raw = p.remote.memory(sp + 0x24, 4)
                        record.update(configuration_wait_status=regs["r0"],
                            configuration_wait_flags_raw=raw.hex(),
                            configuration_wait_flags=struct.unpack("<I", raw)[0])
                    if address in (0x102052E8, 0x103A6B66, 0x103C2954):
                        record.update(configuration_event_code=regs["r0"],
                            configuration_event_raw_parameter=regs["r1"])
                if role == "master" and (address in CONFIG_SYNC_OBSERVERS or
                                          address in SYS_CONFIG_WIRE_OBSERVERS):
                    record.update(configuration_sync_snapshot(p.remote))
                    sp = int(regs["r13"], 16)
                    record.update(stack_address=hex(sp), stack_64bytes=p.remote.memory(sp, 64).hex(),
                        counter_48MHz_raw=p.remote.memory(0x04266008, 8).hex())
                    if address == 0x103C2954 and regs["r0"] == "0x0301000a":
                        pointer = int(regs["r1"], 16)
                        if 0xC0000000 <= pointer < 0xC6000000 - 12:
                            raw = p.remote.memory(pointer, 12)
                            import struct
                            record.update(original_SYS_generation_input_address=hex(pointer),
                                original_SYS_generation_input_bytes=raw.hex(),
                                original_SYS_generation_input_words=list(struct.unpack("<3I", raw)))
                    if address in (0x103C294E, 0x10386304):
                        record["published_configuration_status_arguments"] = [
                            int(regs[k], 16) for k in ("r0", "r1", "r2")]
                    if address == 0x103C28D0:
                        record.update(classified_parent_id=regs["r5"],
                            returned_local_generation_word=int(regs["r0"], 16))
                    if address == 0x103C288A:
                        pointer = int(regs["r3"], 16)
                        if any(lo <= pointer and pointer + 4 < hi for lo, hi in
                               ((0xC0000000, 0xC6000000), (0xC8000000, 0xCB000000))):
                            raw = p.remote.memory(pointer, 4)
                            import struct
                            record.update(original_RAM_generation_load_address=hex(pointer),
                                original_RAM_generation_before_load_bytes=raw.hex(),
                                original_RAM_generation_before_load_word=struct.unpack("<I", raw)[0])
                    if address in SYS_CONFIG_WIRE_OBSERVERS:
                        record.update(SYS_sender_private=p.remote.memory(0xC18A7C20, 0x10).hex(),
                            SYS_sender_adapter_table=p.remote.memory(0xC18A7C30, 0x40).hex(),
                            SYS_backend=p.remote.memory(0xC18A7B7C, 0x78).hex())
                        pointer = int(regs["r0"], 16)
                        if 0xC0000000 <= pointer < 0xC6000000 - 64:
                            record.update(SYS_sender_R0_argument_address=hex(pointer),
                                SYS_sender_R0_argument_bytes=p.remote.memory(pointer, 64).hex())
                        if address == 0x10385D54:
                            target = int(regs["r1"], 16) & ~1
                            if 0x10020000 <= target < 0x10020000 + len(p.blob) - 16:
                                raw = p.blob[target - 0x10020000:target - 0x10020000 + 16]
                                assert p.remote.memory(target, 16) == raw
                                record.update(original_SYS_status_sender_target=hex(target),
                                              original_SYS_status_sender_target_bytes=raw.hex())
                if role == "master" and (address in CONTROLLER_CONTEXT_OBSERVERS or
                                         address in CONTROLLER_NOTIFICATION_OBSERVERS or
                                         address in ORIENTATION_CONFIG_OBSERVERS):
                    import struct
                    context = p.remote.memory(0xC18680D8, 0x34)
                    sp = int(regs["r13"], 16)
                    record.update(aggregate_context_address="0xc18680d8",
                        aggregate_context_52bytes=context.hex(),
                        aggregate_context_mask=struct.unpack_from("<I", context, 0x14)[0],
                        aggregate_context_calculation_flag=struct.unpack_from("<I", context, 0x18)[0],
                        aggregate_context_saved_property=struct.unpack_from("<I", context, 0x2C)[0],
                        stack_address=hex(sp), stack_64bytes=p.remote.memory(sp, 64).hex(),
                        counter_48MHz_raw=p.remote.memory(0x04266008, 8).hex(),
                        controller_aggregate_value=p.remote.memory(0xC18694B0 + 0x44, 4).hex(),
                        policy_group_masks=p.remote.memory(0xC1818BE0 + 0x320, 12).hex())
                    if address == 0x1026D0CE:
                        pointer = int(regs["r0"], 16)
                        if 0xC0000000 <= pointer < 0xC6000000:
                            record.update(aggregate_commit_input_address=hex(pointer),
                                aggregate_commit_input=p.remote.memory(pointer, 16).hex())
                    if (address in CONTROLLER_NOTIFICATION_OBSERVERS or
                            address in ORIENTATION_CONFIG_OBSERVERS):
                        record.update(state_source_C1CF7914=p.remote.memory(0xC1CF7914, 0x300).hex(),
                            state_selector_root_C1807F04=p.remote.memory(0xC1807F04, 0x40).hex(),
                            controller_dependent_state=p.remote.memory(0xC18694B0 + 0xD8, 8).hex())
                        if address in (0x103D7AA0, 0x103D7AC2):
                            pointer = int(regs["r0"], 16)
                            if 0xC0000000 <= pointer < 0xC6000000:
                                record.update(configuration_binder_argument_address=hex(pointer),
                                    configuration_binder_argument=p.remote.memory(pointer, 8).hex())
                        if address == 0x103EFC48:
                            record["upstream_event_code"] = regs["r0"]
                            pointer = int(regs["r1"], 16)
                            if 0xC0000000 <= pointer < 0xC6000000:
                                record.update(upstream_event_payload_address=hex(pointer),
                                    upstream_event_payload=p.remote.memory(pointer, 32).hex())
                if role == "master" and (address in POLICY_OBSERVERS or
                                          address in POLICY_FOLLOWUP_OBSERVERS or
                                          address in POLICY_GROUP2_SOURCE_OBSERVERS or
                                          address in CONTROLLER_PREREQUISITE_OBSERVERS):
                    import struct
                    record["MCU_service0D_lower_state"] = p.remote.memory(0xC18A7C70, 0x60).hex()
                    record["counter_48MHz_raw"] = p.remote.memory(0x04266008, 8).hex()
                    owner = p.remote.memory(0xC1818BE0, 0x390)
                    descriptor = struct.unpack_from("<I", owner, 0x154)[0]
                    record.update(policy_owner=owner.hex(),
                        policy_ready_callback=hex(struct.unpack_from("<I", owner, 0x3C)[0]),
                        policy_current_numeric_state=owner[0x158],
                        policy_current_descriptor=hex(descriptor),
                        policy_state_object=p.remote.memory(descriptor, 0x150).hex() if descriptor else None)
                    record.update(mode_backend6=p.remote.memory(0xC2098804, 0x48).hex(),
                        mode_backend7=p.remote.memory(0xC20987BC, 0x48).hex(),
                        mode_backend6_status=p.remote.memory(0xC185DE80, 0x20).hex(),
                        controller_root=p.remote.memory(0xC18694B0, 0x100).hex())
                    record.update(controller_operation_callbacks=p.remote.memory(0xC23E30E4, 0x80).hex(),
                        controller_deferred_queue=p.remote.memory(0xC23E3E84, 0x60).hex(),
                        lower_request_state=p.remote.memory(0xC188A7D0, 0x50).hex(),
                        lower_request_flags=p.remote.memory(0xC29308FC, 0x30).hex())
                    record.update(lower_current_request=p.remote.memory(0xC2930878, 0x84).hex(),
                        lower_mode_state=p.remote.memory(0xC188A1CC, 0x80).hex(),
                        image_lifecycle_root=p.remote.memory(0xC188A5B8, 0xD0).hex(),
                        image_mode_root=p.remote.memory(0xC188A210, 0x58).hex())
                    if address in (0x10386B7C, 0x1030F1E2):
                        pointer = int(regs["r1"], 16)
                        if 0xC0000000 <= pointer < 0xC4000000:
                            record.update(MCU_completion_argument_address=hex(pointer),
                                MCU_completion_argument=p.remote.memory(pointer, 0x10).hex())
                    if address == 0x10386614:
                        pointer = int(regs["r1"], 16)
                        if 0xC0000000 <= pointer < 0xC4000000:
                            record.update(MCU_decoded_reply_argument_address=hex(pointer),
                                MCU_decoded_reply_argument=p.remote.memory(pointer, 0x10).hex())
                    if address == 0x102F5372:
                        request_pointer = int(regs["r0"], 16)
                        record.update(lower_request_24byte_view=p.remote.memory(request_pointer, 0x18).hex())
                    if address == 0x1020F876:
                        event_pointer = int(regs["r0"], 16)
                        event_data = p.remote.memory(event_pointer, 0x1C)
                        record.update(property_event=event_data.hex(),
                            property_event_code=hex(struct.unpack_from("<I", event_data, 0x10)[0]))
                    if address == 0x1020CA7A:
                        message = int(regs["r1"], 16)
                        record.update(message_address=hex(message),
                            queued_message_header=p.remote.memory(message, 0x20).hex())
                    if address == 0x1020CC60:
                        message = int(regs["r7"], 16)
                        record.update(message_address=hex(message),
                            queued_message_header=p.remote.memory(message, 0x20).hex())
                    if address in (0x1020CBDE, 0x1020CC1C, 0x1020CC44, 0x1020CC4C):
                        message = int(regs["r7"], 16)
                        payload = int(regs["r4"], 16)
                        header = p.remote.memory(message, 0x20)
                        record.update(message_address=hex(message),
                            queued_message_header=header.hex(),
                            queued_message_code=hex(struct.unpack_from("<I", header, 0x10)[0]),
                            decoded_payload_address=hex(payload),
                            decoded_payload_16bytes=p.remote.memory(payload, 0x10).hex())
                    if address == 0x1020E0E8:
                        sp = int(regs["r13"], 16)
                        record.update(producer_event_code=regs["r1"],
                            producer_raw_parameter=regs["r2"],
                            producer_original_caller_return_address=regs["r14"],
                            producer_stack_address=hex(sp),
                            producer_stack_128bytes=p.remote.memory(sp, 128).hex())
                    if address == 0x1020E3FE:
                        pointer = int(regs["r2"], 16)
                        record.update(native_controller_event_code=regs["r1"],
                            native_controller_event_argument=hex(pointer),
                            native_controller_event_argument_32bytes=p.remote.memory(pointer, 32).hex()
                            if 0xC0000000 <= pointer < 0xD0000000 else None,
                            native_policy_auxiliary=p.remote.memory(0xC1818F70, 0x48).hex())
                    if address in (0x1020F7C0, 0x1020F7D0, 0x1020F7DA, 0x1020F7F4):
                        record["native_policy_auxiliary"] = p.remote.memory(0xC1818F70, 0x48).hex()
                        if address == 0x1020F7C0:
                            pointer = int(regs["r1"], 16)
                            record.update(aggregate_input_address=hex(pointer),
                                aggregate_input_16bytes=p.remote.memory(pointer, 16).hex(),
                                aggregate_original_caller_return_address=regs["r14"])
                    if address in CONTROLLER_PREREQUISITE_OBSERVERS:
                        raw_gate = p.remote.memory(0xC1869838, 4)
                        record.update(controller_evaluation_inhibit_address="0xc1869838",
                            controller_evaluation_inhibit_raw=raw_gate.hex(),
                            controller_evaluation_inhibit_numeric=struct.unpack("<I", raw_gate)[0],
                            controller_query_table=p.remote.memory(0xC18695A8, 0x24 * 8).hex())
                    if address == 0x1020CC82:
                        target = int(regs["r2"], 16)
                        record.update(native_task_callback=hex(target),
                            native_task_callback_original_bytes=p.remote.memory(target & ~1, 16).hex())
                    if address in (0x1020D364, 0x1020E154, 0x1020F7F4):
                        sp = int(regs["r13"], 16)
                        message = struct.unpack("<I", p.remote.memory(sp, 4))[0]
                        record.update(message_code=regs["r1"],
                            message_address=hex(message),
                            message_68byte_view=p.remote.memory(message, 0x44).hex() if message else None)
                    if address in (0x10247898, 0x10247A16):
                        report_address = int(regs["r1"], 16)
                        record.update(SYS_config_report_36bytes=p.remote.memory(report_address, 0x24).hex())
                    if address in (0x102A7BD0, 0x10204BDA, 0x1020DAD2):
                        payload = int(regs["r2"], 16)
                        record.update(outward_request_code=regs["r1"],
                            outward_payload_12byte_view=p.remote.memory(payload, 12).hex()
                            if payload >= 0xC0000000 else None)
                if role == "slave" and address in SLAVE_DEVICE_OBSERVERS:
                    sp = int(regs["r13"], 16)
                    record.update(stack_address=hex(sp), stack_256bytes=p.remote.memory(sp, 256).hex())
                    if address == 0x10089E72:
                        obj = int(regs["r1"], 16)
                        record.update(mode_structure_address=hex(obj),
                                      mode_structure_12bytes=p.remote.memory(obj, 12).hex())
                if role == "master" and address in POWER_INPUT_OBSERVERS:
                    record.update(
                        service04_callback_registration=p.remote.memory(0xC18104FC, 0x24).hex(),
                        power_backend_registration=p.remote.memory(0xC1810494, 0x58).hex(),
                        native_KEY_report=p.remote.memory(0xC1F7A720, 0x34).hex(),
                        power_report_112bytes=p.remote.memory(0xC1D53C68, 0x70).hex(),
                        TEMP_root=p.remote.memory(0xC1807F70, 0x10).hex(),
                        power_hub_report_112bytes=p.remote.memory(0xC23A939C, 0x70).hex(),
                        normalized_power_report=p.remote.memory(0xC23A8E9C, 0x70).hex(),
                        power_hub_callbacks=p.remote.memory(0xC23A8DF0, 0xAC).hex(),
                        power_property_state=p.remote.memory(0xC185DEEC, 0x10).hex(),
                        mode_backend6_status=p.remote.memory(0xC185DE80, 0x20).hex(),
                    )
                    if address in (0x103FB78E, 0x10431234):
                        report_pointer = int(regs["r2" if address == 0x103FB78E else "r1"], 16)
                        record.update(power_event_code=regs["r1" if address == 0x103FB78E else "r0"],
                            power_event_payload_address=hex(report_pointer),
                            power_event_payload=p.remote.memory(report_pointer, 0x70).hex()
                            if 0xC0000000 <= report_pointer < 0xD0000000 else None)
                if role == "master" and address in SERIAL_OBSERVERS:
                    record["serial_state"] = p.remote.memory(0xC1808960, 0x78).hex()
                    if address in (0x1020B6D8, 0x1020B766, 0x102053E4):
                        record["original_RX_staging"] = p.remote.memory(0xC1D1AB28, 256).hex()
                    if address == 0x102053E4:
                        descriptor = int(regs["r1"], 16)
                        record["receiver_descriptor_address"] = hex(descriptor)
                        record["receiver_descriptor"] = p.remote.memory(descriptor, 0x18).hex()
                    if address == 0x102055E6:
                        record.update(native_service=regs["r0"], native_route=regs["r1"],
                                      native_payload_length=regs["r2"])
                        record["original_RX_staging"] = p.remote.memory(0xC1D1AB28, 256).hex()
                    if address == 0x10205618:
                        record["native_wire_decoder"] = regs["r3"]
                    if address in (0x1020633C, 0x10204E30):
                        record.update(SYS_event=regs["r0"],
                            SYS_payload_address=regs["r1"],
                            SYS_manager_registration=p.remote.memory(0xC18A79E4, 0x20).hex())
                        if address == 0x1020633C:
                            record["native_SYS_upper_callback"] = regs["r12"]
                    if address in (0x1020562A, 0x1020663A):
                        import struct
                        if address == 0x1020562A:
                            obj = int(regs["r0"], 16)
                            raw = p.remote.memory(obj, 8)
                            tag, payload = struct.unpack("<II", raw)
                            record.update(decoded_object_address=hex(obj), decoded_object=raw.hex(),
                                decoded_object_tag=tag, native_service_consumer=regs["r1"],
                                decoded_payload_128byte_view=p.remote.memory(payload, 128).hex())
                        else:
                            record.update(SYS_event=regs["r0"], SYS_payload_address=regs["r1"],
                                SYS_payload_128byte_view=p.remote.memory(int(regs["r1"], 16), 128).hex(),
                                SYS_registered_callbacks=p.remote.memory(0xC18A7A54, 0x28).hex())
                if role == "master" and address in (0x10637D16, 0x103A5F6E,
                        0x10324D4E, 0x10324D54, 0x103A58C8, 0x103A58DE, 0x103A5A0C,
                        0x104026D8, 0x104026F0, 0x103A5A44):
                    sp = int(regs["r13"], 16)
                    record["stack_address"] = hex(sp)
                    record["stack_128bytes"] = p.remote.memory(sp, 128).hex()
                    record["resource_buffer_root"] = p.remote.memory(0xC1808CA0, 0x20).hex()
                    record["image_memory_config"] = p.remote.memory(0xC26A0DDC, 0x60).hex()
                    if address in IPUBF_ORIGIN_OBSERVERS:
                        record['IPUBF_origin'] = dict(phase_low_byte=int(regs['r0'], 16) & 0xff
                            if address == 0x104026F0 else None,
                            destination_pointer=hex(int.from_bytes(bytes.fromhex(record['resource_buffer_root'])[4:8], 'little')),
                            actual_submit={k: regs[k] for k in ('r0', 'r1', 'r2', 'r3')}
                                if address == 0x103A5A44 else None,
                            guest_memory_written=False, extra_MMIO_read_issued=False)
                if not args.quiet_observers:
                    print(role, name, hex(address), "LR", regs["r14"], flush=True)
                if role == "master" and address == args.stop_at:
                    report["engines"][role]["passive_checkpoint_reached"] = True
                    continue
                if address in ABORT_OBSERVERS[role]:
                    abort_snapshot = p.snapshot("first original " + role + " CPU abort", reply)
                    report["engines"][role]["original_CPU_abort"] = record
                    record["original_CPU_abort_snapshot"] = abort_snapshot
                    fault_core = next(core for core in abort_snapshot["cores"]
                                      if core["thread"] == thread)
                    system = fault_core["system_registers"]
                    data_abort = address in (0x10103610, 0x100350C0)
                    record["original_fault_pages_by_bank"] = {}
                    def bank_register(stem, bank):
                        names = ((stem + "_S", stem + "_EL1_S") if bank == "S" else
                                 (stem + "_NS", stem + "_EL1", stem))
                        return next(((key, int(system[key], 16)) for key in names if key in system), (None, None))
                    for bank in ("S", "NS"):
                        fault_name, fault_virtual = bank_register("DFAR" if data_abort else "IFAR", bank)
                        status_name, fault_status = bank_register("DFSR" if data_abort else "IFSR", bank)
                        ttbr_name, ttbr_raw = bank_register("TTBR0", bank)
                        if fault_virtual is None or ttbr_raw is None or not fault_status:
                            continue
                        ttbcr_name, ttbcr = bank_register("TTBCR", bank)
                        sctlr_name, sctlr = bank_register("SCTLR", bank)
                        keys = dict(fault_address=fault_name, fault_status=status_name,
                                    SCTLR=sctlr_name, TTBCR=ttbcr_name, TTBR=ttbr_name)
                        if sctlr is None or ttbcr is None:
                            record["original_fault_pages_by_bank"][bank] = {
                                "virtual": hex(fault_virtual), "MMU_enable_or_format_unresolved": True,
                                "observed_system_register_keys": keys}
                            continue
                        if not sctlr & 1:
                            record["original_fault_pages_by_bank"][bank] = {
                                "virtual": hex(fault_virtual), "MMU_disabled": True,
                                "observed_system_register_keys": keys}
                            continue
                        # Short-descriptor TTBR0 alignment depends on N. Keep
                        # LPAE explicit rather than decoding it as a section.
                        if ttbcr & (1 << 31):
                            record["original_fault_pages_by_bank"][bank] = {"LPAE_descriptor_walk_unresolved": True}
                            continue
                        n = ttbcr & 7
                        use_ttbr1 = bool(n and fault_virtual >= (1 << (32 - n)))
                        if use_ttbr1:
                            ttbr_name, ttbr_raw = bank_register("TTBR1", bank)
                            keys["TTBR"] = ttbr_name
                            if ttbr_raw is None:
                                record["original_fault_pages_by_bank"][bank] = {
                                    "virtual": hex(fault_virtual), "TTBR1_unavailable": True,
                                    "observed_system_register_keys": keys}
                                continue
                        alignment_bits = 14 if use_ttbr1 else 14 - n
                        ttbr = ttbr_raw & ~((1 << alignment_bits) - 1)
                        descriptor_address = ttbr + (fault_virtual >> 20) * 4
                        try:
                            raw = p.remote.memory(descriptor_address, 4)
                        except Exception as error:
                            record["original_fault_pages_by_bank"][bank] = {
                                "virtual": hex(fault_virtual), "TTBR0": hex(ttbr),
                                "level1_address": hex(descriptor_address),
                                "descriptor_read_error": str(error)}
                            continue
                        descriptor = int.from_bytes(raw, "little")
                        page = dict(virtual=hex(fault_virtual), selected_TTBR=hex(ttbr),
                            uses_TTBR1=use_ttbr1, MMU_enabled=True,
                            observed_system_register_keys=keys, original_SCTLR=hex(sctlr),
                            level1_address=hex(descriptor_address), level1_bytes=raw.hex(),
                            descriptor_type=descriptor & 3,
                            section_physical=hex((descriptor & 0xfff00000) | (fault_virtual & 0xfffff))
                                if descriptor & 3 == 2 and not descriptor & (1 << 18) else None,
                            short_descriptor_TTBCR=hex(ttbcr))
                        record["original_fault_pages_by_bank"][bank] = page
                    record["original_fault_page"] = record["original_fault_pages_by_bank"].get("S")
                    fault_pc = (int(regs["r14"], 16) - (8 if data_abort else 4)) & ~1
                    record["fault_instruction_address_from_original_abort_LR"] = hex(fault_pc)
                    if 0x10020000 <= fault_pc < 0x10020000 + len(p.blob) - 16:
                        record["original_fault_instruction_bytes"] = p.remote.memory(fault_pc, 16).hex()
                        record["local_ROM_fault_instruction_bytes"] = p.blob[fault_pc-0x10020000:fault_pc-0x10020000+16].hex()
                    record["abort_handler_left_paused_without_changing_guest_state"] = True
                    report["engines"][role]["abort_stack"] = p.remote.memory(
                        int(regs["r13"], 16), 0x100).hex()
                    if role == "master":
                        record.update(fallback_callback_object_bytes=p.remote.memory(0xC1864CD0, 0x24).hex(),
                            region50_notification_bytes=p.remote.memory(0xC20A4248, 0x30).hex(),
                            region50_descriptor_bytes=p.remote.memory(0xC185F468, 0x18).hex())
                    continue
                if watch_stop:
                    assert p.remote.command("z2,c1818f08,4") == "OK"
                    assert p.remote.command("Hc" + thread) == "OK"
                    p.remote.send("s")
                    step = p.remote.receive()
                    if not step.startswith("T05"):
                        report["engines"][role]["watchpoint_step_exit_reply"] = step
                        continue
                    record.update(watched_value_after_original_single_step=
                        p.remote.memory(0xC1818F08, 4).hex(),
                        policy_owner_after_original_single_step=p.remote.memory(0xC1818BE0, 0x390).hex())
                    assert p.remote.command("Hc-1") == "OK"
                    if report["policy_group2_watchpoint"]["hits"] < 16:
                        assert p.remote.command("Z2,c1818f08,4") == "OK"
                    p.remote.send("c")
                    p.running = True
                    continue
                assert p.remote.command(f"z1,{address:x},2") == "OK"
                assert p.remote.command("Hc" + thread) == "OK"
                p.remote.send("s")
                try:
                    step = p.remote.receive()
                except (EOFError, ConnectionError, OSError) as error:
                    record["step_connection_closed"] = str(error)
                    continue
                if not step.startswith("T05"):
                    report["engines"][role]["step_exit_reply"] = step
                    continue
                assert p.remote.command("Hc-1") == "OK"
                limit = (1 if recorded_ram_checked is not None and role == 'master' and address == HOOK else
                         4 if args.ipu_resource_origin_trace and address in IPUBF_ORIGIN_OBSERVERS else
                         64 if address in GPIO_ROUTE_OBSERVERS and address in (0x1036AC1A, 0x1036AC1E, 0x1036AC22) else
                         12 if address in GPIO_ROUTE_OBSERVERS else
                         24 if args.peer_business_trace_only else
                         160 if address in RESOURCE_OBSERVERS else
                         80 if address == 0x1020F876 else
                         24 if (address in POLICY_OBSERVERS or
                                address in POLICY_FOLLOWUP_OBSERVERS or
                                address in POLICY_GROUP2_SOURCE_OBSERVERS or
                                address in CONTROLLER_PREREQUISITE_OBSERVERS or
                                address in CONTROLLER_CONTEXT_OBSERVERS or
                                address in CONTROLLER_NOTIFICATION_OBSERVERS or
                                address in ORIENTATION_CONFIG_OBSERVERS or
                                address in CONFIG_NOTIFICATION_OBSERVERS or
                                address in CONFIG_SYNC_OBSERVERS or
                                address in SYS_CONFIG_WIRE_OBSERVERS or
                                address in GENNOR_LIFECYCLE_OBSERVERS or
                                address in DMA_ALLOCATION_OBSERVERS) else
                         8 if address in SERIAL_OBSERVERS or address in POWER_INPUT_OBSERVERS else
                         12 if address == 0x10200CAC else 3)
                if counts[role][address] < limit:
                    if not (args.conditional_seed_only_observers and
                            report.get("diagnostic_region47_RAM_seed_performed")):
                        assert p.remote.command(f"Z1,{address:x},2") == "OK"
                    else:
                        del enabled[role][address]
                else:
                    del enabled[role][address]
                p.remote.send("c")
                p.running = True
        stopped_finals = {}
        if args.stop_both_before_snapshot:
            from expeed_task_observer import pause_both, observe
            gate = pause_both(engines, directory / "两端EXPEED停止证据.json")
            report["two_EXPEED_final_stop_gate"] = gate
            for role, p in engines.items():
                stopped_finals[role] = p.snapshot("end of natural entry execution window", gate["roles"][role]["stop_reply"])
            if loader_runtime_reference is not None:
                from loader_runtime_audit import observe as observe_loader_runtime
                report['complete_Loader_runtime_audit'] = observe_loader_runtime(
                    engines['master'], loader_runtime_reference,
                    engines['master'].directory / 'Loader-runtime', gate)
            if task_plan is not None:
                report["stopped_task_RAM_observations"] = {}
                for role, p in engines.items():
                    report["stopped_task_RAM_observations"][role] = observe(
                        p, task_plan["roles"][role], p.directory / "task-RAM", gate)
        for role, p in engines.items():
            if p.process.poll() is None:
                if args.stop_both_before_snapshot:
                    final = stopped_finals[role]
                else:
                    if p.running:
                        p.remote.sock.sendall(b"\x03")
                        reply = p.remote.receive()
                        p.running = False
                    else:
                        reply = p.remote.command("?")
                    final = p.snapshot("end of natural entry execution window", reply)
                report["engines"][role]["final_CPU_fault_registers"] = [dict(
                    thread=core["thread"], registers={k: v for k, v in core["system_registers"].items()
                    if k.startswith(("DFAR", "DFSR", "IFAR", "IFSR"))}) for core in final["cores"]]
                report["engines"][role]["counter_48MHz_raw"] = p.remote.memory(0x04266008, 8).hex()
                if role == "master":
                    # Read-only snapshots, not injected ready/configuration.
                    report["engines"][role]["input_gate"] = p.remote.memory(0xC1811E50, 0x78).hex()
                    report["engines"][role]["TEMP_root"] = p.remote.memory(0xC1807F70, 0x10).hex()
                    report["engines"][role]["queue_state"] = p.remote.memory(0xC1808930, 0x48).hex()
                    report["engines"][role]["peer_channel6_original_object"] = p.remote.memory(0xC28F8738, 0x640).hex()
                    for label, address, length in (
                        ("native_boot_flag_object", 0xC185E164, 0x30),
                        ("native_boot_tasks", 0xC20A1730, 0x80),
                        ("resource_buffer_root", 0xC1808CA0, 0x20),
                        ("system_policy_current", 0xC1818BE0 + 0x154, 12),
                        ("policy_owner", 0xC1818BE0, 0x390),
                        ("policy_state0_object", 0xC1819858, 0x150),
                        ("mode_backend6", 0xC2098804, 0x48),
                        ("mode_backend7", 0xC20987BC, 0x48),
                        ("mode_backend6_status", 0xC185DE80, 0x20),
                        ("controller_root", 0xC18694B0, 0x100),
                        ("controller_evaluation_inhibit", 0xC1869838, 4),
                        ("controller_query_table", 0xC18695A8, 0x24 * 8),
                        ("controller_aggregate_context", 0xC18680D8, 0x34),
                        ("controller_dependent_state", 0xC18694B0 + 0xD8, 8),
                        ("state_source_C1CF7914", 0xC1CF7914, 0x300),
                        ("state_selector_root_C1807F04", 0xC1807F04, 0x40),
                        ("orientation_configuration_eventflags", 0xC1875334, 0x30),
                        ("region21_descriptor", 0xC185EDF4, 0x1C),
                        ("region57_descriptor", 0xC185F1E4, 0x1C),
                        ("source11_descriptor", 0xC185E8E8, 0x2C),
                        ("source12_descriptor", 0xC185E914, 0x2C),
                        ("region21_notification_record", 0xC20A3348 + 21 * 0x30, 0x30),
                        ("region57_notification_record", 0xC20A3348 + 57 * 0x30, 0x30),
                        ("controller_operation_callbacks", 0xC23E30E4, 0x80),
                        ("controller_deferred_queue", 0xC23E3E84, 0x60),
                        ("lower_request_state", 0xC188A7D0, 0x50),
                        ("lower_request_flags", 0xC29308FC, 0x30),
                        ("lower_current_request", 0xC2930878, 0x84),
                        ("lower_mode_state", 0xC188A1CC, 0x80),
                        ("image_lifecycle_root", 0xC188A5B8, 0xD0),
                        ("image_mode_root", 0xC188A210, 0x58),
                        ("MCU_service0D_upper_callbacks", 0xC2B28CC8, 0x30),
                        ("MCU_service0D_lower_state", 0xC18A7C70, 0x60),
                        ("startup_state", 0xC185E548, 0x24),
                        ("startup_version_report", 0xC20AF0D0, 0xC),
                        ("EX_MCU_private", 0xC18A7C20, 0x10),
                        ("EX_MCU_backend", 0xC18A7B7C, 0x78),
                        ("panel_root", 0xC1808500, 0x18),
                        ("display_readiness", 0xC1875330, 0x30),
                        ("serial_state", 0xC1808960, 0x78),
                        ("original_RX_staging", 0xC1D1AB28, 256),
                        ("original_TX_staging", 0xC1D1A8C4, 256),
                        ("SYS_report_callbacks", 0xC18A7A54, 0x28),
                        ("SYS_manager_registration", 0xC18A79E4, 0x20),
                        ("power_backend_registration", 0xC1810494, 0x58),
                        ("service04_callback_registration", 0xC18104FC, 0x24),
                        ("native_KEY_report", 0xC1F7A720, 0x34),
                        ("power_report_112bytes", 0xC1D53C68, 0x70),
                        ("power_report_state", 0xC1865110, 0x120),
                        ("power_hub_report_112bytes", 0xC23A939C, 0x70),
                        ("normalized_power_report", 0xC23A8E9C, 0x70),
                        ("power_hub_callbacks", 0xC23A8DF0, 0xAC),
                        ("power_property_state", 0xC185DEEC, 0x10),
                        ("native_SAISO_UI_properties_180x", 0xC253DC28, 12),
                        ("native_SAISO_property_1810", 0xC253DC68, 4),
                        ("native_SAISO_AE_properties", 0xC253D850, 0x228),
                        ("native_SAISO_gate_properties", 0xC253E230, 0x138),
                        ("native_SAISO_publish", 0xC1876508, 0x30),
                        ("native_SAISO_workspace", 0xC1875350, 0x68),
                        ("native_APPLV_state", 0xC181D9E4, 0xE4),
                        ("native_lens_property_2005", 0xC253E618, 4),
                        ("native_group20_ready", 0xC253D72C, 4),
                    ):
                        report["engines"][role][label] = p.remote.memory(address, length).hex()
                    report["engines"][role].update(configuration_sync_snapshot(p.remote))
                    report["engines"][role].update(gennor_lifecycle_snapshot(p.remote))
                    if args.dma_allocation_only or args.no_observers:
                        # Verify the actual end-of-window resource bytes, not
                        # just a nonzero descriptor or a completed IRQ. This
                        # reads paused guest RAM and compares with the original
                        # ROM; it neither programs DMA nor writes guest state.
                        root = bytes.fromhex(report["engines"][role]["resource_buffer_root"])
                        destination = int.from_bytes(root[4:8], "little")
                        if destination == 0xC0C00000:
                            source, length = 0x107A99F4, 0x3B1C0
                            observed = p.remote.memory(destination, length)
                            original = p.remote.memory(source, length)
                            target = p.directory / "original-resource-DMA-destination.bin"
                            target.write_bytes(observed)
                            report["engines"][role]["resource_DMA_byte_comparison"] = dict(
                                source=hex(source), destination=hex(destination), bytes=length,
                                saved_destination=str(target),
                                destination_sha256=hashlib.sha256(observed).hexdigest(),
                                source_sha256=hashlib.sha256(original).hexdigest(),
                                bytes_equal=observed == original,
                                read_only_paused_guest_capture=True,
                                physical_DMA_timing_and_transfer_verified=False)
                    if args.serial_trace:
                        raw = bytes.fromhex(report["engines"][role]["serial_state"])
                        import struct
                        report["engines"][role]["serial_GPIO_objects"] = []
                        for off in (0x20, 0x24, 0x28, 0x2C, 0x3C, 0x40, 0x44, 0x48):
                            pointer = struct.unpack_from("<I", raw, off)[0]
                            report["engines"][role]["serial_GPIO_objects"].append(dict(
                                owner_offset=hex(off), address=hex(pointer),
                                bytes=p.remote.memory(pointer, 0x38).hex() if pointer else None))
                    if args.resource_trace:
                        for label, address, length in (
                            ("boot_worker0_stack", 0xC519A000, 0x2000),
                            ("boot_worker1_stack", 0xC519C000, 0x2000),
                            ("backend_getter_tables", 0xC185DF40, 0x260),
                        ):
                            data = p.remote.memory(address, length)
                            path = p.directory / (label + ".bin")
                            path.write_bytes(data)
                            report["engines"][role][label] = dict(
                                address=hex(address), length=length, path=str(path),
                                sha256=hashlib.sha256(data).hexdigest())
                    for thread in p.threads:
                        p.remote.command("Hg" + thread)
                        regs = p.remote.registers()
                        sp = int(regs["r13"], 16)
                        data = p.remote.memory(sp, 256)
                        path = p.directory / ("natural-core-" + thread + "-stack.bin")
                        path.write_bytes(data)
                        report["engines"][role].setdefault("core_stacks", []).append(dict(
                            thread=thread, sp=hex(sp), path=str(path),
                            bytes=data.hex()))
                    if args.integrated or args.legacy_single:
                        path = p.directory / "natural-entry-display.ppm"
                        p.monitor.command("screendump", {"filename": str(path)})
                        from PIL import Image
                        with Image.open(path) as im:
                            im.save(path.with_suffix(".png"))
                            report["engines"][role]["display"] = dict(
                                png=str(path.with_suffix(".png")), size=list(im.size),
                                distinct_colors=len(im.getcolors(im.width * im.height)),
                                ppm=str(path),
                                ppm_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                png_sha256=hashlib.sha256(path.with_suffix(".png").read_bytes()).hexdigest(),
                                sha256_format="PPM; legacy sha256 field retained for compatibility",
                                sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                else:
                    report["engines"][role]["queue_state"] = p.remote.memory(0xC1006F68, 0x30).hex()
                    report["engines"][role]["slave_run_local_flash11FA"] = p.remote.memory(0x11FA0000, 0x40).hex()
        if args.menu_session:
            save(directory / "原双端启动记录.json", report)
            from dual_menu_session import run_session
            run_session(engines, enabled, directory, report, plan=args.menu_plan,
                        extra_regions=args.menu_config_region,
                        sensor_dependency_trace=args.sensor_dependency_trace)
    except Exception as error:
        report.update(error=str(error), traceback=traceback.format_exc())
    finally:
        for role, p in engines.items():
            p.close()
            if p.report.get("debugger_API_byte_ledgers"):
                report["engines"][role]["debugger_API_byte_ledgers"] = p.report["debugger_API_byte_ledgers"]
            report["engines"][role].update(first_unmodeled=p.report["first_unmodeled"],
                                          first_hardware_boundary=p.report["first_hardware_boundary"],
                                          native_wire_boundary_lines=p.report["native_wire_boundary_lines"],
                                          native_wire_ACK_write_lines=p.report["native_wire_ACK_write_lines"],
                                          native_wire_known_wait_lines=p.report["native_wire_known_wait_lines"],
                                          exit_code=p.report["exit_code"],
                                          virtual_SD_cards=p.report.get("virtual_SD_cards", []),
                                          QEMU_process_lifecycle=p.report["QEMU_process_lifecycle"],
                                          build_sha256=p.manifest["binary_sha256"])
        report["seconds"] = round(time.monotonic() - start, 4)
        returns = [o for o in report["observations"] if o["role"] == "master"
                   and o["address"] == "0x10200cf8"]
        report["native_boot_phase_returns"] = [dict(
            worker=int(o["registers"]["r4"], 16), phase=int(o["registers"]["r6"], 16),
            original_wait_return=int(o["registers"]["r0"], 16)) for o in returns]
        required = {(worker, phase) for worker in range(2) for phase in range(6)}
        seen = {(row["worker"], row["phase"]) for row in report["native_boot_phase_returns"]
                if row["original_wait_return"] == 1}
        report["native_six_phase_barriers_observed_complete"] = required <= seen
        report["native_six_phase_barriers_scope"] = (
            "Both original RTOS startup workers inside the master EXPEED; "
            "this does not validate the slave EXPEED, MCU, or full camera startup")
        expected_roles = ("master", "slave") if not args.legacy_single else ("master",)
        lifecycle = {}
        for role in expected_roles:
            p = engines.get(role)
            lifecycle[role] = p.report["QEMU_process_lifecycle"] if p else {
                "role": role, "launch": "unknown", "exit": "unknown"}
        report["QEMU_process_accounting"] = process_summary(lifecycle, expected_roles)
        report["owned_QEMU_exited"] = bool(engines) and all(
            p.process is not None and p.process.poll() is not None for p in engines.values())
        report["legacy_field_scopes"] = {
            "owned_QEMU_exited": "nonempty handled process set only; expected roles are checked separately"}
        save(directory / "结果.json", report)
        print(json.dumps(dict(output=str(directory), error=report.get("error"),
                              first_unmodeled={k: v.get("first_unmodeled") for k,v in report["engines"].items()},
                              observations=len(report["observations"])), ensure_ascii=False), flush=True)
    if report.get("error"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
