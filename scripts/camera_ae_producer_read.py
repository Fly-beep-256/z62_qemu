"""Read the fixed AE producer inputs from a connected Z6II C1.70.

Reuses the retained standard-property and F001/F036/F002/CloseSession
protocol. Each F036 request is at most 128 bytes within the fixed RAM
windows below. The readings are sequential running-state references.
"""
import argparse
from datetime import datetime
from pathlib import Path
import struct
import uuid

from camera_native_ui_read import (
    Connection, PROPERTY_CODES, ROM_FILE, ROM_SHA256, allowed, sha,
)
from camera_battery_read import parse_identity
from z62_common import ROOT, identity, now, save


RAM_WINDOWS = (
    (0xC1887CB0, 512, 'AE_service_owner'),
    (0xC20F2A00, 488, 'AE_default_input'),
    (0xC25DAD04, 64, 'AE_queue_slots'),
    (0xC25DB2A0, 64, 'AE_worker_context'),
    (0xC25DC2B0, 96, 'AE_service_state'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
)

# Original ROM literals in 10210114/102101E4 identify the task owner and
# separate control/work regions. This profile reads those fixed locations;
# pointers found in the results are not followed through USB.
AESEF_RAM_WINDOWS = (
    (0xC20F29D4, 44, 'AESEF_task_owner'),
    (0xC185F488, 80, 'AESEF_control_storage'),
    (0xC20F2A00, 488, 'AE_default_input'),
    (0xC20F3820, 128, 'AESEF_work_buffer'),
    (0xC20F4008, 64, 'AESEF_work_state'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
)

# Fixed locations from the verified original mask4 request ABI. The context
# address is the retained two-pass camera reference, not a pointer followed
# from a USB response. Its fields are interpreted only when the request slot
# still names that same object.
REFERENCE_CONTEXT = 0xC2CFD580
PRODUCER_CONTROL_RAM_WINDOWS = (
    (0xC185F484, 56, 'AESEF_request_control'),
    (0xC1887CB0, 128, 'AE_qualification_owner'),
    (0xC25DAD24, 64, 'AE_request_queues'),
    (0xC25DB174, 4, 'AE_mask80_claim'),
    (0xC1887DB0, 72, 'AE_request_preparation'),
)
PRODUCER_RAM_WINDOWS = AESEF_RAM_WINDOWS + PRODUCER_CONTROL_RAM_WINDOWS + (
    (REFERENCE_CONTEXT, 96, 'reference_context_header'),
    (REFERENCE_CONTEXT + 0x140, 16, 'reference_context_tail'),
)

# Fixed original-ROM literals, not addresses obtained from USB replies.
# 102313C0 names C25DAD24; 10231810 names C1887CDC. 10237C74 names
# C1887FFC (callback base -0x68), and 10239848 names C1888080.
UPSTREAM_RAM_WINDOWS = AESEF_RAM_WINDOWS + PRODUCER_CONTROL_RAM_WINDOWS + (
    (0xC25DACB8, 44, 'main_AE_task_owner'),
    (0xC25DACE4, 128, 'main_AE_four_queues'),
    (0xC1887F94, 104, 'upstream_context_and_callbacks'),
    (0xC269EAA0, 44, 'upstream_context_task_owner'),
    (0xC1888080, 64, 'adapter_control_and_callbacks'),
    (0xC269F9C8, 44, 'adapter_task_owner'),
)

# Fixed locations verified in the retained original-ROM key payload contract
# (10436600, 1038DC0C, 1038DB5E) and exposure-path report. This profile pairs
# the sequential AE reference with input state and the lens/display gates.
# It sends no key events and does not follow pointers returned by the camera.
INPUT_REFERENCE_RAM_WINDOWS = UPSTREAM_RAM_WINDOWS + (
    (0xC25DB254, 32, 'AE_selected_input_queue'),
    (0xC1887D8C, 4, 'AE_selector_pending_mask'),
    (0xC25DB19C, 4, 'AE_claim20000_context'),
    (0xC1F7A720, 104, 'key_current_previous_payload'),
    (0xC1F7A5AC, 160, 'key_normalized_fields'),
    (0xC1811BB0, 88, 'key_callback_control'),
    (0xC25D6FC0, 52, 'key_builder_payload'),
    (0xC18879F8, 8, 'key_phase0_descriptor'),
    (0xC253E618, 4, 'lens_mounted_property'),
    (0xC253D72C, 4, 'exposure_group20_ready_property'),
)

# Retained two-pass input reference names C1818BE0 in normalized word0.
# The ROM scatter record covers this fixed object. 1020df2a copies input at
# +180, then 1020e052 loads the callback table pointer at +154 and calls its
# +8 entry directly. No extra vtable dereference or USB pointer chase occurs.
REFERENCE_INPUT_CONTEXT = 0xC1818BE0
INPUT_DISPATCH_RAM_WINDOWS = (
    (0xC1F7A5AC, 160, 'key_normalized_fields'),
    (0xC1811BB0, 88, 'key_callback_control'),
    (REFERENCE_INPUT_CONTEXT + 0x140, 64, 'reference_input_dispatch'),
    (REFERENCE_INPUT_CONTEXT + 0x180, 128, 'reference_input_copy'),
    (REFERENCE_INPUT_CONTEXT + 0x2F0, 16, 'reference_input_flags'),
    (REFERENCE_INPUT_CONTEXT + 0x350, 64, 'reference_input_policy'),
    (0xC253E618, 4, 'lens_mounted_property'),
    (0xC253D72C, 4, 'exposure_group20_ready_property'),
    (0xC20F2A00, 488, 'AE_default_input'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
)

# Fixed ROM literals from the retained first-writer contract. This profile
# compares the job-message producer and its existing-input queue with AE
# output. Queue pointers are reported as values and never followed via USB.
FIRST_WRITER_RAM_WINDOWS = (
    (0xC23D9EE8, 44, 'job_message_owner'),
    (0xC23D9F14, 36, 'job_message_container'),
    (0xC23DC9CC, 32, 'old_job_queue'),
    (0xC1868BF0, 128, 'job_callback_flags'),
    (0xC1868C70, 128, 'job_sequence_and_handshake'),
    (0xC23DC0A0, 24, 'input_block_template'),
    (0xC26A0B50, 96, 'associated_allocator_state'),
    (0xC1888180, 8, 'associated_allocator_flags'),
    (0xC25DB254, 32, 'selected_input_queue'),
    (0xC1887D8C, 4, 'selector_pending_mask'),
    (0xC253E618, 4, 'lens_mounted_property'),
    (0xC253D72C, 4, 'exposure_group20_ready_property'),
    (0xC20F2A00, 488, 'AE_default_input'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
)

# Fixed original-ROM literals in 103702DA and 102E1CA0/102E176E. These
# windows cover software descriptors and owners only. In particular this
# profile never reads the 2C08011C hardware word, nor follows descriptor
# register pointers returned over USB.
SERIAL_STOP_RAM_WINDOWS = (
    (0xC1805B74, 8, 'serial_stop_DMA_descriptor_slots'),
    (0xC1805BDC, 48, 'serial_stop_control'),
    (0xC1807ABC, 128, 'serial_stop_service_state'),
    (0xC1CF7468, 44, 'serial_stop_dispatch_owner'),
    (0xC1CF74D8, 44, 'serial_stop_completion_owner'),
    (0xC185F484, 56, 'AESEF_request_control'),
    (0xC20F29D4, 44, 'AESEF_task_owner'),
    (0xC20F2A00, 488, 'AE_default_input'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
)

# 1031AD1A loads 1031ADB4=C23DC474, adds F4 and passes the word at
# C23DC568 to 103B0F02 and, conditionally, 1031AAAC. C1868CE4 is the
# sequence counter incremented at 10316B3E; it is retained separately so
# earlier samples of that counter cannot be mistaken for this item root.
# Neither pointer is followed through USB. The application-manager window
# is already in camera_native_ui_read's retained MENU contract.
ORIGINAL_ITEM_ROOT_RAM_WINDOWS = (
    (0xC23DC568, 4, 'original_item_root'),
    (0xC1868CE4, 4, 'original_item_sequence_counter'),
    (0xC1868BF0, 64, 'original_item_mode_and_flags'),
    (0xC1868A70, 12, 'original_item_condition'),
    (0xC23DC9CC, 32, 'old_job_queue'),
    (0xC23D9F14, 36, 'job_message_container'),
    (0xC185F484, 56, 'AESEF_request_control'),
    (0xC20F2A00, 488, 'AE_default_input'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
    (0xC253E618, 4, 'lens_mounted_property'),
    (0xC253D72C, 4, 'exposure_group20_ready_property'),
    (0xC1811E50, 144, 'application_manager_and_reports'),
)

# Fixed original-ROM sources in the bounded request-gate contract. The
# reference compares queue state, +40/+50/+58 routing and the actual callback
# slots with valid AE output. It does not follow context pointers over USB.
REQUEST_GATE_RAM_WINDOWS = (
    (0xC1887CB0, 128, 'main_AE_routing_and_request_gate'),
    (0xC25DAD04, 96, 'pending_ready_membership_queues'),
    (0xC1887F94, 68, 'source_request_and_callbacks'),
    (0xC25DB19C, 4, 'claim20000_slot'),
    (0xC25DACB8, 44, 'main_AE_task_owner'),
    (0xC269EAA0, 44, 'source_request_task_owner'),
    (0xC25DB254, 32, 'selected_input_queue'),
    (0xC1887D8C, 4, 'selector_pending_mask'),
    (0xC185F484, 56, 'AESEF_request_control'),
    (0xC20F2A00, 488, 'AE_default_input'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
    (0xC253E618, 4, 'lens_mounted_property'),
    (0xC253D72C, 4, 'exposure_group20_ready_property'),
)

# Fixed original-ROM literals verified from the package's master image:
# 1026F1D4 = C23D9978, the 92-byte source returned by 1026EE16;
# 1023AB80 = C269F9F4, whose byte +18 gates consumption in 1023A932.
# 1022FB18 resolves C1887CB0; byte +7 selects the mask4 request path.
# These are fixed RAM reads, and no pointer returned by USB is followed.
MASK4_RAM_WINDOWS = (
    (0xC1887CB0, 128, 'main_AE_mask4_owner'),
    (0xC269F9F4, 32, 'mask4_adapter_flags_and_control'),
    (0xC23D9978, 92, 'mask4_default_input92'),
    (0xC20F2A00, 488, 'AE_default_input'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
    (0xC253E618, 4, 'lens_mounted_property'),
    (0xC253D72C, 4, 'exposure_group20_ready_property'),
)

# Fixed ROM literals in 1029693E/102DF04C identify the SDES/TG callback
# objects. 102D8210 minus 5C identifies CAPTG's event control; the retained
# capture-configuration contract identifies C18A7798. These are software
# RAM windows only: no hardware status register or returned pointer is read.
CAPTURE_CALLBACK_RAM_WINDOWS = (
    (0xC1806D3C, 40, 'SDES_source_callback_object'),
    (0xC1806D64, 96, 'TG_source_callback_object'),
    (0xC18A75D8, 96, 'CAPTG_event_control'),
    (0xC18A7798, 48, 'capture_configuration_callback_owner'),
    (0xC185F484, 56, 'AESEF_request_control'),
    (0xC20F2A00, 488, 'AE_default_input'),
    (0xC253D85C, 44, 'AE_rational_1603_through_1609'),
    (0xC253DC28, 68, 'exposure_1800_through_1810'),
    (0xC253E618, 4, 'lens_mounted_property'),
    (0xC253D72C, 4, 'exposure_group20_ready_property'),
)

# Original literals 1026E8F8=C1868490 and 1026E904=C23D9728 identify
# the owner inspected by the 02010001/02010002 callback and its software
# message object. Read the fixed objects alongside the existing callback
# and AE references. No callback pointer, hardware register or USB-returned
# address is followed. A registered callback does not prove execution.
CAPTG_STATE_RAM_WINDOWS = CAPTURE_CALLBACK_RAM_WINDOWS + (
    (0xC1868490, 256, 'CAPTG_upstream_owner'),
    (0xC23D9728, 64, 'CAPTG_message_owner'),
)


def words(data, offset=0, count=None):
    count = count if count is not None else (len(data)-offset)//4
    return list(struct.unpack_from('<'+'I'*count, data, offset))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--passes', type=int, choices=range(1, 4), default=2)
    parser.add_argument('--profile', choices=('service', 'aesef', 'producer-gates', 'upstream',
                                              'input-reference', 'input-dispatch',
                                              'first-writer', 'serial-stop',
                                              'original-item-root', 'request-gates',
                                              'mask4-source', 'capture-callbacks',
                                              'captg-state'), default='service')
    args = parser.parse_args(argv)
    windows = {'service': RAM_WINDOWS, 'aesef': AESEF_RAM_WINDOWS,
               'producer-gates': PRODUCER_RAM_WINDOWS, 'upstream': UPSTREAM_RAM_WINDOWS,
               'input-reference': INPUT_REFERENCE_RAM_WINDOWS,
               'input-dispatch': INPUT_DISPATCH_RAM_WINDOWS,
               'first-writer': FIRST_WRITER_RAM_WINDOWS,
               'serial-stop': SERIAL_STOP_RAM_WINDOWS,
               'original-item-root': ORIGINAL_ITEM_ROOT_RAM_WINDOWS,
               'request-gates': REQUEST_GATE_RAM_WINDOWS,
               'mask4-source': MASK4_RAM_WINDOWS,
               'capture-callbacks': CAPTURE_CALLBACK_RAM_WINDOWS,
               'captg-state': CAPTG_STATE_RAM_WINDOWS}[args.profile]
    if sha(ROM_FILE.read_bytes()) != ROM_SHA256:
        parser.error('Master ROM identity differs')
    directory = args.out or ROOT/'results'/(
        datetime.now().strftime('%Y%m%d-%H%M%S')+'-camera-ae-producer-'+uuid.uuid4().hex[:6])
    if not directory.is_absolute():
        directory = ROOT/directory
    directory = directory.resolve()
    directory.relative_to((ROOT/'results').resolve())
    directory.mkdir(parents=True, exist_ok=False)
    execution_sources = []
    for path in (Path(__file__).resolve(), ROOT/'scripts/camera_native_ui_read.py',
                 ROOT/'scripts/camera_battery_read.py', ROOT/'scripts/z62_common.py'):
        target = directory/'execution-sources'/path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        execution_sources.append(dict(**identity(target, directory),
                                      original_relative_path=str(path.relative_to(ROOT))))
    report = dict(
        schema='z62.camera-ae-producer-read/1', started=now(), complete=False,
        fixed_profile=args.profile,
        reference_ROM=identity(ROM_FILE, ROOT),
        reference_identity_scope='locked package ROM; camera model/version; physical ROM read unavailable',
        physical_ROM_bytes_verified=False, atomic_snapshot=False,
        physical_cold_boot_observed=False, original_callback_execution_observed=False,
        camera_reset=False, memory_or_property_writes=0,
        operator_lens_or_standby_state='not independently confirmed; standard properties retained',
        command_allowlist='standard reads; F001/F002; fixed RAM F036 <=128 bytes',
        fixed_RAM_windows=[dict(address=hex(address), bytes=size, label=label)
                           for address, size, label in windows],
        normal_properties={}, samples=[], execution_sources=execution_sources,
    )
    connection = None
    print('Camera AE read: '+str(directory), flush=True)
    try:
        connection = Connection(directory)
        connection.windows = list(windows)
        # Validate the imported protocol guard before claiming the device.
        for address, size, _ in windows:
            for offset in range(0, size, 128):
                request = (0xF036, address+offset, min(128, size-offset), 0, 0)
                if not allowed(0x94FF, request, connection.windows):
                    raise ValueError('Declared fixed RAM request rejected')
        report['USB'] = connection.details
        connection.util.claim_interface(connection.dev, connection.interface)
        connection.claimed = True
        connection.require(0x1002, (1,), 'OpenSession')
        connection.session_owned = True
        info = parse_identity(connection.require(0x1001, (), 'GetDeviceInfo'))
        report['identity'] = info
        if (info['model'], info['version']) != ('Z 6_2', 'V1.70'):
            raise ValueError('Connected model/version differs from locked ROM')
        print('Identity: '+info['model']+' '+info['version'], flush=True)
        for code in PROPERTY_CODES:
            payload = connection.require(0x1015, (code,), 'normal-property-'+hex(code))
            if payload is None:
                raise ValueError('Missing standard property payload')
            report['normal_properties'][hex(code)] = dict(
                raw_hex=payload.hex(), unsigned_value=int.from_bytes(payload, 'little'))
        connection.diagnostic_attempted = True
        connection.require(0x94FD, (0xF001, 0, 0, 0, 0), 'EnterF001')
        connection.diagnostic_active = True
        for index in range(args.passes):
            started, values, retained_windows = now(), {}, []
            for address, size, label in windows:
                data, retained = connection.read(address, size, f'pass{index+1}-'+label)
                values[label] = data
                retained_windows.append(retained)
            source = values['AE_default_input']
            rational = values['AE_rational_1603_through_1609']
            sample = dict(
                index=index+1, started=started, finished=now(), windows=retained_windows,
                AE_default_input_header=words(source, 0, 24),
                AE_default_input_1608_pair=words(source, 0x30, 2),
                AE_default_input_1609_pair=words(source, 0x20, 2),
                callback_pointer_is_running_state_only=True,
                AE_rational_words={hex(prop): words(rational, offset, 2)
                                   for prop, offset in ((0x1603, 0), (0x1608, 28), (0x1609, 36))},
                exposure_words_1800_1801_1802=words(values['exposure_1800_through_1810'], 0, 3),
                exposure_word_1810=words(values['exposure_1800_through_1810'], 0x40, 1)[0],
            )
            if args.profile == 'service':
                sample.update(
                    AE_service_owner_words=words(values['AE_service_owner']),
                    adapter_callback_table_slot=hex(words(values['AE_service_owner'], 0x104, 1)[0]),
                    AE_queue_words=words(values['AE_queue_slots']),
                    AE_worker_context_words=words(values['AE_worker_context']),
                    AE_service_state_words=words(values['AE_service_state']))
            elif args.profile in ('capture-callbacks', 'captg-state'):
                sdes = values['SDES_source_callback_object']
                tg = values['TG_source_callback_object']
                control = values['CAPTG_event_control']
                sample.update(
                    SDES_source_callback_words=words(sdes),
                    SDES_callback_10=hex(words(sdes, 0x10, 1)[0]),
                    TG_source_callback_words=words(tg),
                    TG_callback_34=hex(words(tg, 0x34, 1)[0]),
                    TG_callback_38=hex(words(tg, 0x38, 1)[0]),
                    CAPTG_event_control_words=words(control),
                    CAPTG_upstream_callback_04=hex(words(control, 4, 1)[0]),
                    CAPTG_countdown_0c=words(control, 0x0C, 1)[0],
                    CAPTG_countdown_10=words(control, 0x10, 1)[0],
                    capture_configuration_callback_owner_words=words(
                        values['capture_configuration_callback_owner']),
                    AESEF_request_control_words=words(values['AESEF_request_control']),
                    lens_mounted_property=words(values['lens_mounted_property'])[0],
                    exposure_group20_ready_property=words(values['exposure_group20_ready_property'])[0],
                    callback_execution_observed=False,
                    hardware_status_registers_read=False,
                    callback_pointer_payloads_read=False)
                if args.profile == 'captg-state':
                    owner = values['CAPTG_upstream_owner']
                    sample.update(
                        CAPTG_upstream_owner_words=words(owner),
                        CAPTG_state_byte_00=owner[0],
                        CAPTG_substate_byte_0c=owner[0x0C],
                        CAPTG_owner_callback_28=hex(words(owner, 0x28, 1)[0]),
                        CAPTG_owner_count_64=words(owner, 0x64, 1)[0],
                        CAPTG_owner_flag_wrapper_b0_words=words(owner, 0xB0, 4),
                        CAPTG_message_owner_words=words(values['CAPTG_message_owner']),
                        CAPTG_event_or_state_transition_observed=False)
            elif args.profile == 'serial-stop':
                sample.update(
                    serial_DMA_descriptor_pointers=[hex(value) for value in
                        words(values['serial_stop_DMA_descriptor_slots'])],
                    serial_control_words=words(values['serial_stop_control']),
                    serial_service_words=words(values['serial_stop_service_state']),
                    serial_dispatch_owner_words=words(values['serial_stop_dispatch_owner']),
                    serial_completion_owner_words=words(values['serial_stop_completion_owner']),
                    AESEF_request_control_words=words(values['AESEF_request_control']),
                    AESEF_task_owner_words=words(values['AESEF_task_owner']),
                    serial_hardware_status_read=False,
                    serial_descriptor_registers_read=False,
                    serial_stop_execution_observed=False,
                    physical_serial_register_reset_verified=False)
            elif args.profile == 'original-item-root':
                application = values['application_manager_and_reports']
                sample.update(
                    original_item_root=hex(words(values['original_item_root'])[0]),
                    original_item_root_address='0xc23dc568',
                    original_item_sequence_counter=words(values['original_item_sequence_counter'])[0],
                    original_item_sequence_counter_address='0xc1868ce4',
                    original_item_mode=words(values['original_item_mode_and_flags'], 0x10, 1)[0],
                    original_item_condition_byte=values['original_item_condition'][9],
                    original_item_mode_and_flag_words=words(values['original_item_mode_and_flags']),
                    old_job_queue_words=words(values['old_job_queue']),
                    job_message_container_words=words(values['job_message_container']),
                    AESEF_request_control_words=words(values['AESEF_request_control']),
                    lens_mounted_property=words(values['lens_mounted_property'])[0],
                    exposure_group20_ready_property=words(values['exposure_group20_ready_property'])[0],
                    application_manager_words=words(application),
                    application_selector_byte=application[0x10],
                    original_item_payload_read=False,
                    original_item_producer_execution_observed=False)
            elif args.profile == 'mask4-source':
                source = values['mask4_default_input92']
                adapter = values['mask4_adapter_flags_and_control']
                sample.update(
                    mask4_source92_words=words(source),
                    mask4_source92_nonzero=any(source),
                    main_AE_mode_byte_7=values['main_AE_mask4_owner'][7],
                    mask4_adapter_flag_byte_18=adapter[0x18],
                    mask4_adapter_flag_mask6=adapter[0x18] & 6,
                    lens_mounted_property=words(values['lens_mounted_property'])[0],
                    exposure_group20_ready_property=words(values['exposure_group20_ready_property'])[0],
                    mask4_producer_or_consumer_execution_observed=False)
            elif args.profile == 'request-gates':
                owner = values['main_AE_routing_and_request_gate']
                queues = values['pending_ready_membership_queues']
                source = values['source_request_and_callbacks']
                control = values['AESEF_request_control']
                sample.update(
                    main_AE_routing_words=words(owner),
                    main_AE_alternative_route_40=words(owner, 0x40, 1)[0],
                    main_AE_default_route_50=words(owner, 0x50, 1)[0],
                    main_AE_request_gate_58=words(owner, 0x58, 1)[0],
                    context_queues={name: dict(zip(
                        ('head', 'tail', 'count', 'reserve', 'pool', 'free_list', 'last_node', 'aux'),
                        words(queues, offset, 8)))
                        for name, offset in (('pending', 0), ('ready', 0x20), ('membership', 0x40))},
                    source_mailbox=hex(words(source, 0x10, 1)[0]),
                    source_callback_041A001D=hex(words(source, 0x3C, 1)[0]),
                    source_callback_041A000A=hex(words(source, 0x40, 1)[0]),
                    claim20000_context=hex(words(values['claim20000_slot'])[0]),
                    selected_input_queue_words=words(values['selected_input_queue']),
                    selector_pending_mask=hex(words(values['selector_pending_mask'])[0]),
                    main_AE_task_owner_words=words(values['main_AE_task_owner']),
                    source_request_task_owner_words=words(values['source_request_task_owner']),
                    AESEF_busy_byte=control[0],
                    AESEF_context=hex(words(control, 0x24, 1)[0]),
                    AESEF_callback=hex(words(control, 0x28, 1)[0]),
                    lens_mounted_property=words(values['lens_mounted_property'])[0],
                    exposure_group20_ready_property=words(values['exposure_group20_ready_property'])[0],
                    context_pointer_payloads_read=False,
                    request_or_callback_execution_observed=False)
            elif args.profile == 'first-writer':
                container = values['job_message_container']
                queue = values['old_job_queue']
                flags = values['job_callback_flags']
                sample.update(
                    job_message_owner_words=words(values['job_message_owner']),
                    job_message_container_words=words(container),
                    job_message_buffer=hex(words(container, 0, 1)[0]),
                    job_message_stride_word=words(container, 4, 1)[0],
                    job_message_capacity=words(container, 8, 1)[0],
                    job_message_count=words(container, 12, 1)[0],
                    old_job_queue_words=words(queue),
                    old_job_queue_head=hex(words(queue, 0, 1)[0]),
                    old_job_queue_tail=hex(words(queue, 4, 1)[0]),
                    job_callback_flags_words=words(flags),
                    job_callback_active=words(flags, 0x1C, 1)[0],
                    job_callback_deferred=words(flags, 0x20, 1)[0],
                    job_callback_ready=words(flags, 0x30, 1)[0],
                    job_sequence_and_handshake_words=words(values['job_sequence_and_handshake']),
                    input_block_template_words=words(values['input_block_template']),
                    associated_allocator_words=words(values['associated_allocator_state']),
                    associated_allocator_flag_words=words(values['associated_allocator_flags']),
                    selected_input_queue_words=words(values['selected_input_queue']),
                    selector_pending_mask=hex(words(values['selector_pending_mask'])[0]),
                    lens_mounted_property=words(values['lens_mounted_property'])[0],
                    exposure_group20_ready_property=words(values['exposure_group20_ready_property'])[0],
                    job_callback_execution_observed=False,
                    queue_pointer_payloads_read=False)
            elif args.profile == 'input-dispatch':
                normalized = values['key_normalized_fields']
                control = values['key_callback_control']
                dispatch = values['reference_input_dispatch']
                sample.update(
                    fixed_reference_input_context=hex(REFERENCE_INPUT_CONTEXT),
                    normalized_context=hex(words(normalized)[0]),
                    reference_input_context_matches=words(normalized)[0] == REFERENCE_INPUT_CONTEXT,
                    reference_input_callback_table=hex(words(dispatch, 0x14, 1)[0]),
                    reference_input_dispatch_words=words(dispatch),
                    reference_input_copy_words=words(values['reference_input_copy']),
                    reference_input_flag_bytes=values['reference_input_flags'].hex(),
                    reference_input_policy_words=words(values['reference_input_policy']),
                    key_normalized_words=words(normalized),
                    key_callback=hex(words(control)[0]),
                    key_deferred_mask=words(control, 0x10, 1)[0],
                    key_notification_suppressed=words(control, 0x14, 1)[0],
                    lens_mounted_property=words(values['lens_mounted_property'])[0],
                    exposure_group20_ready_property=words(values['exposure_group20_ready_property'])[0],
                    input_consumer_execution_observed=False)
            else:
                sample.update(AESEF_task_owner_words=words(values['AESEF_task_owner']),
                              AESEF_control_words=words(values['AESEF_control_storage']),
                              AESEF_work_buffer_words=words(values['AESEF_work_buffer']),
                              AESEF_work_state_words=words(values['AESEF_work_state']))
                if args.profile in ('producer-gates', 'upstream', 'input-reference'):
                    control = values['AESEF_request_control']
                    owner = values['AE_qualification_owner']
                    context = words(control, 0x24, 1)[0]
                    sample.update(
                        request_busy_byte=control[0],
                        mask4_context=hex(context),
                        mask4_callback=hex(words(control, 0x28, 1)[0]),
                        qualification_selector=owner[0],
                        qualification_comparison_words=words(owner, 0x44, 2),
                        claim_mask80_context=hex(words(values['AE_mask80_claim'], 0, 1)[0]),
                        request_queue_words=words(values['AE_request_queues']),
                        request_preparation_words=words(values['AE_request_preparation']),
                        upstream_request_or_callback_execution_observed=False)
                if args.profile == 'producer-gates':
                    sample.update(
                        fixed_reference_context=hex(REFERENCE_CONTEXT),
                        reference_context_matches_request_slot=context == REFERENCE_CONTEXT,
                        reference_context_header_words=words(values['reference_context_header']),
                        reference_context_tail_words=words(values['reference_context_tail']))
                if args.profile in ('upstream', 'input-reference'):
                    upstream = values['upstream_context_and_callbacks']
                    adapter = values['adapter_control_and_callbacks']
                    sample.update(
                        main_AE_task_owner_words=words(values['main_AE_task_owner']),
                        main_AE_four_queue_words=words(values['main_AE_four_queues']),
                        upstream_pending_context=hex(words(upstream, 0x10, 1)[0]),
                        upstream_callback_041A001D=hex(words(upstream, 0x3C, 1)[0]),
                        upstream_callback_041A000A=hex(words(upstream, 0x40, 1)[0]),
                        upstream_context_task_owner_words=words(values['upstream_context_task_owner']),
                        adapter_control_words=words(adapter),
                        adapter_callback_041A000A=hex(words(adapter, 0x2C, 1)[0]),
                        adapter_completion_callback=hex(words(adapter, 0x28, 1)[0]),
                        adapter_task_owner_words=words(values['adapter_task_owner']))
                if args.profile == 'input-reference':
                    key_control = values['key_callback_control']
                    sample.update(
                        selected_input_queue_words=words(values['AE_selected_input_queue']),
                        selector_pending_mask=hex(words(values['AE_selector_pending_mask'])[0]),
                        claim20000_context=hex(words(values['AE_claim20000_context'])[0]),
                        key_current_previous_words=words(values['key_current_previous_payload']),
                        key_normalized_words=words(values['key_normalized_fields']),
                        key_builder_words=words(values['key_builder_payload']),
                        key_descriptor_words=words(values['key_phase0_descriptor']),
                        key_callback=hex(words(key_control)[0]),
                        key_deferred_mask=words(key_control, 0x10, 1)[0],
                        key_notification_suppressed=words(key_control, 0x14, 1)[0],
                        lens_mounted_property=words(values['lens_mounted_property'])[0],
                        exposure_group20_ready_property=words(values['exposure_group20_ready_property'])[0],
                        input_consumer_execution_observed=False)
            report['samples'].append(sample)
            save(directory/'summary.json', report)
            print('Sample '+str(index+1)+': input='+str(sample['AE_default_input_1608_pair'])+
                  '/'+str(sample['AE_default_input_1609_pair'])+
                  ' AE='+str(sample['AE_rational_words']), flush=True)
        report['complete'] = True
    except BaseException as exc:
        report['error'] = type(exc).__name__+': '+str(exc)
        print(report['error'], flush=True)
    finally:
        if connection is not None:
            connection.cleanup(report)
            report['transaction_count'] = len(connection.transactions)
        report['finished'] = now()
        save(directory/'summary.json', report)
        files = [identity(path, directory) for path in sorted(directory.iterdir()) if path.is_file()]
        save(directory/'manifest.json', dict(schema='z62.camera-ae-producer-manifest/1',
                                             files=files, execution_files=execution_sources))
        print('Saved: '+str(directory), flush=True)
    return int(not (report['complete'] and report.get('F002_exit_ok') and
                    report.get('CloseSession_ok') and report.get('USB_release_ok')))


if __name__ == '__main__':
    raise SystemExit(main())
