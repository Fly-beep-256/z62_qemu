"""Declared external pad sequence; never writes guest RAM or protocol packets."""
import argparse
from pathlib import Path
import time
from z62_common import now, read, save, identity

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--prepare-dir', type=Path, required=True)
    ap.add_argument('--run-dir', type=Path, required=True)
    ap.add_argument('--safety-timeout', type=float, default=120)
    args = ap.parse_args()
    run = args.run_dir.resolve()
    report = dict(schema='z62.external-pad-scenario/1', started=now(),
                  script=identity(__file__), guest_state_writes=0,
                  physical_button_names_verified=False, events=[],
                  ACK_is_business_acceptance=False, complete=False)
    result = run / 'native-gpio-scenario-result.json'
    state_paths = dict(GPIO=run / 'MCU/gpio-host-state.json', PCAL=run / 'MCU/pcal-host-state.json')
    try:
        limit = time.monotonic() + 100
        while time.monotonic() < limit:
            locked = read(args.prepare_dir / '锁定命令与输入.json')
            gs, ps = read(state_paths['GPIO']), read(state_paths['PCAL'])
            if locked and gs and ps and gs.get('running') is True:
                break
            if (run / '运行验收证据.json').exists():
                raise RuntimeError('Coordinator ended before external pad scenario attached')
            time.sleep(.1)
        else:
            raise TimeoutError('MCU running external-input acknowledgement not observed')
        origin = gs['host_monotonic_ns'] / 1e9
        inputs = dict(GPIO=Path(locked['explicit_MCU_gpio_host_input_file']),
                      PCAL=Path(locked['explicit_MCU_host_input_file']))

        def wait_at(seconds):
            while time.monotonic() < origin + seconds:
                state = read(state_paths['GPIO'])
                if state and state.get('running') is False:
                    raise RuntimeError('MCU stopped before external pad sequence finished')
                time.sleep(.1)

        def drive(kind, mask, levels, label, port='G'):
            previous = read(state_paths[kind])
            command = dict(sequence=previous['sequence'] + 1, mask=mask,
                           levels=levels, label=label)
            if kind == 'GPIO':
                command['port'] = port
            save(inputs[kind], command)
            limit = time.monotonic() + 15
            while time.monotonic() < limit:
                state = read(state_paths[kind])
                if state and state.get('sequence') == command['sequence']:
                    report['events'].append(dict(kind='external_pad_ack', pad_kind=kind,
                      request=command, acknowledgement=state,
                      host_elapsed=round(time.monotonic() - origin, 3)))
                    return
                if state and state.get('running') is False:
                    raise RuntimeError('MCU exited before pad acknowledgement: ' + label)
                time.sleep(.1)
            raise TimeoutError('External pad acknowledgement: ' + label)

        schedule = [(25, 'GPIO', 0x20, 0, 'PC5:close-low', 'C'),
                    (165, 'PCAL', 0x200, 0, 'MENU-pad:low', 'G'),
                    (169, 'PCAL', 0x200, 0x200, 'MENU-pad:release', 'G'),
                    (195, 'GPIO', 0x02, 0, 'PG1:low', 'G'),
                    (199, 'GPIO', 0x02, 0x02, 'PG1:release', 'G'),
                    (280, 'GPIO', 0x04, 0, 'PG2:low', 'G'),
                    (284, 'GPIO', 0x04, 0x04, 'PG2:release', 'G')]
        report['schedule'] = [dict(at_host_seconds=t, pad_kind=k, mask=m, levels=l,
                                  label=n, port=p, within_budget=t+15 < args.safety_timeout)
                              for t,k,m,l,n,p in schedule]
        for t, kind, mask, levels, label, port in schedule:
            if t + 15 >= args.safety_timeout:
                continue
            wait_at(t)
            drive(kind, mask, levels, label, port)
        report['complete'] = True
        report['status'] = 'declared_external_inputs_delivered; camera_function_not_implied'
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        report['status'] = 'scenario_incomplete'
    report['finished'] = now()
    if run.exists():
        save(result, report)
    print(report['status'], flush=True)
    return int(not report['complete'])

if __name__ == '__main__':
    raise SystemExit(main())
