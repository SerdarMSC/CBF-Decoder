#!/usr/bin/env python3
"""
caesar_struct.py - Structural CBF (Caesar) parser.

Python port of the structure readers in jglim/CaesarSuite (MIT):
CFFHeader -> CTF string table -> ECU -> Presentations -> DiagServices
-> input preparations (parameter name, bit position, bit size).

Unlike cbf_parser.py (string/offset scanning), this walks the real
object tables, so for every diagnostic service it gives the exact
request template and where each parameter sits in the request.

Usage:
  CaesarStruct.exe  (no arguments / double-click)        # pick CBF file(s) -> CSV
  python3 caesar_struct.py IC_204.CBF                    # list all services
  python3 caesar_struct.py A.CBF B.CBF --csv             # export to A_services.csv, B_services.csv
  python3 caesar_struct.py IC_204.CBF -f Displaytest     # filter by name
  python3 caesar_struct.py IC_204.CBF -f Zeichenkette --json out.json
"""
import argparse
import json
import struct
import sys

STUB_HEADER_SIZE = 0x410


class R:
    """Little-endian reader with Caesar bitflag helpers."""

    def __init__(self, data):
        self.d = data
        self.p = 0

    def seek(self, p):
        self.p = p

    def _u(self, fmt, n):
        v = struct.unpack_from(fmt, self.d, self.p)[0]
        self.p += n
        return v

    def i32(self): return self._u('<i', 4)
    def u32(self): return self._u('<I', 4)
    def i16(self): return self._u('<h', 2)
    def u16(self): return self._u('<H', 2)
    def u8(self): return self._u('<B', 1)
    def i8(self): return self._u('<b', 1)
    def f32(self): return self._u('<f', 4)

    def cstr(self, p):
        e = self.d.index(b'\0', p)
        raw = self.d[p:e]
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return raw.decode('cp1252', errors='replace')


class Flags:
    """Caesar bitflag cursor: each field is present only if its bit is set."""

    def __init__(self, r, value):
        self.r = r
        self.v = value

    def _on(self):
        on = self.v & 1
        self.v >>= 1
        return bool(on)

    def i32(self, d=0): return self.r.i32() if self._on() else d
    def u32(self, d=0): return self.r.u32() if self._on() else d
    def i16(self, d=0): return self.r.i16() if self._on() else d
    def u16(self, d=0): return self.r.u16() if self._on() else d
    def u8(self, d=0): return self.r.u8() if self._on() else d
    def i8(self, d=0): return self.r.i8() if self._on() else d
    def f32(self, d=0.0): return self.r.f32() if self._on() else d

    def string(self, base):
        if not self._on():
            return None
        off = self.r.i32()
        return self.r.cstr(off + base)

    def dump(self, base, size):
        if not self._on():
            return b''
        off = self.r.i32()
        return self.r.d[off + base: off + base + size]


# ---------------------------------------------------------------- headers

def read_cff(r):
    r.seek(STUB_HEADER_SIZE)
    h = {'size': r.i32()}
    h['base'] = r.p
    f = Flags(r, r.u16())
    h['caesar_version'] = f.i32()
    h['gpd_version'] = f.i32()
    h['ecu_count'] = f.i32()
    h['ecu_offset'] = f.i32()
    h['ctf_offset'] = f.i32()
    h['string_pool_size'] = f.i32()
    f.i32(); f.i32(); f.i32()          # DSC offset/count/entry size
    h['cbf_version'] = f.string(h['base'])
    h['gpd_version_str'] = f.string(h['base'])
    return h


def read_strings(r, cff):
    """CTF language 0 string table (index -> text)."""
    base = cff['base'] + cff['ctf_offset']
    r.seek(base)
    f = Flags(r, r.u16())
    f.i32(); f.string(base); f.i16(); f.i32()
    lang_count = f.i32()
    lang_table = f.i32() + base
    if lang_count == 0:
        return []
    r.seek(lang_table)
    lang_base = r.i32() + lang_table
    r.seek(lang_base)
    f = Flags(r, r.u16())
    f.string(lang_base); f.i16(); f.i32(); f.i32()
    count = f.i32()
    table = cff['size'] + STUB_HEADER_SIZE + 4
    out = []
    for i in range(count):
        r.seek(table + i * 4)
        out.append(r.cstr(table + r.i32()))
    return out


# ---------------------------------------------------------------- ECU

POOLS = ['variant', 'diagjob', 'dtc', 'env', 'vcdomain',
         'presentations', 'internal_presentations', 'unk']


def read_ecu(r, cff, base):
    r.seek(base)
    flags = r.u32()
    ext = r.u16()
    r.i32()
    f = Flags(r, flags)
    e = {'base': base}
    e['qualifier'] = f.string(base)
    e['name_ctf'] = f.i32(-1)
    e['desc_ctf'] = f.i32(-1)
    f.string(base)
    for _ in range(4):
        f.i32()
    for _ in range(3):
        f.string(base)
    data_base = cff['string_pool_size'] + STUB_HEADER_SIZE + cff['size'] + 4
    f.i16(); f.i16(); f.i16(); f.i32(); f.i16(); f.i32()
    pools = {}
    for i, name in enumerate(POOLS):
        if name == 'env':
            off = f.i32() + data_base
            cnt = f.i32()
            esz = f.i32()
            f = Flags(r, ext)            # first 32 flags exhausted here
            f.i32()
        else:
            off = f.i32() + data_base
            cnt = f.i32()
            esz = f.i32()
            f.i32()
        pools[name] = (off, cnt, esz)
    e['pools'] = pools
    return e


def pool_entries(r, pool):
    off, cnt, esz = pool
    out = []
    for i in range(cnt):
        r.seek(off + i * esz)
        out.append(r.i32() + off)
    return out


# ---------------------------------------------------------------- presentations

def read_scale(r, base, strings):
    r.seek(base)
    f = Flags(r, r.u16())
    s = {'enum_low': f.i32(), 'enum_up': f.i32()}
    f.i32(); f.i32()
    s['mul'] = f.f32(); s['add'] = f.f32()
    f.i32(); f.i32(); f.i32(); f.i32()
    d = f.i32(-1)
    s['text'] = strings[d] if 0 <= d < len(strings) else None
    return s


def read_presentation(r, base, strings):
    r.seek(base)
    flags = r.u32()
    ext = r.u16()
    f = Flags(r, flags)
    p = {'qualifier': f.string(base)}
    f.i32(-1)
    scale_off = f.i32(-1)
    scale_cnt = f.i32()
    for _ in range(8):
        f.i32()
    f.i16(); f.i16(); f.i16()
    unit = f.i32(-1)
    f.i32(); f.i32()
    p['enum_max'] = f.i32()
    f.i32(-1); f.i32(); f.i32(-1); f.i32(-1); f.i32(); f.i32(-1)
    p['type_length_1a'] = f.i32(-1)
    p['internal_type'] = f.i8(-1)
    p['type_1c'] = f.i8(-1)
    f.i8()
    p['sign'] = f.i8()
    p['byte_order'] = f.i8()
    f.i32()
    f = Flags(r, ext)
    p['type_length_21'] = f.i32()
    p['unit'] = strings[unit] if 0 <= unit < len(strings) else None
    scales = []
    if scale_cnt > 0 and scale_off != -1:
        tb = base + scale_off
        for i in range(scale_cnt):
            r.seek(tb + i * 4)
            try:
                scales.append(read_scale(r, tb + r.i32(), strings))
            except Exception:
                break
    p['scales'] = scales
    return p


# ---------------------------------------------------------------- preparations

INT_SIZES = [0, 1, 4, 8, 16, 32, 64]


def prep_size(prep, ecu_ctx, req_len):
    mode = prep['mode']
    mE, mH, mL = mode & 0xF000, mode & 0xFF0, mode & 0xF
    if (mode & 0xF00) == 0x300:
        if mH == 0x320:
            return INT_SIZES[mL], 'const_int'
        if mH == 0x330:
            return prep['alt_bitwidth'], 'const_dump'
        return None, 'const_unhandled'
    if prep['system_param'] == -1:
        if mE == 0x8000:
            pres = ecu_ctx['internal_pres'][prep['info_pool']]
            kind = 'internal_pres'
        elif mE == 0x2000:
            pres = ecu_ctx['pres'][prep['pres_pool']]
            kind = 'pres'
        else:
            return None, 'unknown'
        prep['presentation'] = pres
        n = pres['type_length_1a'] if pres['type_length_1a'] > 0 else pres['type_length_21']
        if pres['type_1c'] == 0:
            n *= 8
        return n, kind
    if mH == 0x410:
        if prep['system_param'] - 0x10 == 0:
            return ((req_len & 0xFF) - prep['bitpos'] // 8) * 8, 'extended_dump'
        return None, 'sysparam'
    if mH == 0x420:
        return INT_SIZES[mL], 'special_int'
    if mH == 0x430:
        return prep['alt_bitwidth'], 'special_dump'
    return None, 'unhandled'


def read_prep(r, base, bitpos, mode, strings):
    r.seek(base)
    f = Flags(r, r.u32())
    p = {'bitpos': bitpos, 'mode': mode}
    p['qualifier'] = f.string(base)
    n = f.i32(-1)
    p['name'] = strings[n] if 0 <= n < len(strings) else None
    f.u8(); f.u8()
    p['alt_bitwidth'] = f.i32()
    f.i32()
    p['info_pool'] = f.i32()
    p['pres_pool'] = f.i32()
    f.i32()
    p['system_param'] = f.i16(-1)
    f.i16()
    dsz = f.i32()
    p['dump'] = f.dump(base, dsz).hex().upper()
    return p


# ---------------------------------------------------------------- services

SERVICE_TYPES = {5: 'DATA', 7: 'DOWNLOAD', 10: 'FUNCTION', 19: 'JOB',
                 21: 'SESSION', 22: 'STORED_DATA', 23: 'ROUTINE',
                 24: 'IO_CONTROL', 26: 'VC_WRITE', 27: 'VC_READ'}


def read_service(r, base, strings, ecu_ctx):
    r.seek(base)
    flags = r.u32()
    ext = r.u32()
    f = Flags(r, flags)
    s = {'qualifier': f.string(base)}
    n = f.i32(-1); d = f.i32(-1)
    s['name'] = strings[n] if 0 <= n < len(strings) else None
    s['description'] = strings[d] if 0 <= d < len(strings) else None
    st = f.u16()
    s['type'] = SERVICE_TYPES.get(st, st)
    f.u16()
    s['client_access_level'] = f.u16()
    s['security_access_level'] = f.u16()
    f.i32(); f.i32(); f.i32(); f.i32(); f.i32(); f.i32()
    f.string(base)
    u_cnt = f.i32(); u_off = f.i32()
    f.i32(); f.i32()
    rq_cnt = f.i16(); rq_off = f.i32()
    out_cnt = f.i32(); out_off = f.i32()
    rq = b''
    if rq_cnt > 0:
        rq = r.d[base + rq_off: base + rq_off + rq_cnt]
    s['request'] = rq.hex().upper()
    s['request_len'] = len(rq)

    def preps(table, count):
        out = []
        for i in range(count):
            r.seek(table + i * 10)
            off = r.i32(); bp = r.i32(); mode = r.u16()
            p = read_prep(r, table + off, bp, mode, strings)
            try:
                size, kind = prep_size(p, ecu_ctx, len(rq))
            except Exception as ex:
                size, kind = None, f'error:{ex}'
            p['bits'] = size
            p['kind'] = kind
            out.append(p)
        return out

    s['inputs'] = preps(base + u_off, u_cnt) if u_cnt > 0 else []
    outs = []
    ob = base + out_off
    for i in range(out_cnt if out_cnt > 0 else 0):
        r.seek(ob + i * 8)
        c = r.i32(); o = r.i32()
        if c > 0:
            outs.extend(preps(ob + o, c))
    s['outputs'] = outs
    return s


# ---------------------------------------------------------------- driver

def parse(path):
    data = open(path, 'rb').read()
    r = R(data)
    if not data.startswith(b'CBF-TRANSLATOR-VERSION'):
        print('warning: unexpected header', file=sys.stderr)
    cff = read_cff(r)
    strings = read_strings(r, cff)
    ecus = []
    tbl = cff['ecu_offset'] + cff['base']
    for i in range(cff['ecu_count']):
        r.seek(tbl + i * 4)
        e = read_ecu(r, cff, tbl + r.i32())
        ctx = {
            'pres': [read_presentation(r, a, strings) for a in pool_entries(r, e['pools']['presentations'])],
            'internal_pres': [read_presentation(r, a, strings) for a in pool_entries(r, e['pools']['internal_presentations'])],
        }
        services = []
        for a in pool_entries(r, e['pools']['diagjob']):
            try:
                services.append(read_service(r, a, strings, ctx))
            except Exception as ex:
                services.append({'qualifier': f'<parse error @0x{a:X}: {ex}>'})
        e['services'] = services
        ecus.append(e)
    return cff, ecus


def fmt_prep(p, indent='    '):
    bits = p['bits']
    byte = p['bitpos'] // 8
    loc = f"byte {byte}" + (f".{p['bitpos'] % 8}" if p['bitpos'] % 8 else '')
    size = f"{bits} bit" if bits is not None else '? bit'
    if bits and bits % 8 == 0 and p['bitpos'] % 8 == 0:
        size += f" ({bits // 8} B)"
    line = f"{indent}{loc:<10} {size:<16} {p['qualifier'] or ''}"
    if p.get('name'):
        line += f"  [{p['name']}]"
    line += f"  <{p['kind']}>"
    pres = p.get('presentation')
    if pres and pres['scales']:
        enums = [f"{sc['enum_low']}={sc['text']}" for sc in pres['scales'] if sc['text']]
        if enums:
            line += '\n' + indent + '           enum: ' + ', '.join(enums[:20])
    if p['kind'].startswith('const') and p['dump']:
        line += f"  const={const_hex(p)}"
    return line


CSV_COLUMNS = [
    'ecu', 'service', 'service_name', 'service_type', 'security_level',
    'request_template', 'request_len', 'direction', 'param_index',
    'byte', 'bit', 'size_bits', 'size_bytes', 'param', 'param_name',
    'kind', 'presentation', 'const_value', 'enum_values', 'description',
]


def const_hex(p):
    """Constant parameter value as request bytes (e.g. RoutineIdentifier -> 0006)."""
    kind = str(p.get('kind', ''))
    dump = p.get('dump') or ''
    if not kind.startswith('const') or not dump:
        return ''
    raw = bytes.fromhex(dump)
    bits = p.get('bits') or 0
    if kind == 'const_int' and bits and bits % 8 == 0:
        n = bits // 8
        return int.from_bytes(raw[:4], 'little').to_bytes(n, 'big').hex().upper()
    return raw.hex().upper()


def service_rows(ecu_name, s):
    """One CSV row per parameter (request and response); one row if a service has none."""
    base = {
        'ecu': ecu_name,
        'service': s.get('qualifier') or '',
        'service_name': s.get('name') or '',
        'service_type': s.get('type', ''),
        'security_level': s.get('security_access_level', ''),
        'request_template': s.get('request', ''),
        'request_len': s.get('request_len', ''),
        'description': (s.get('description') or '').replace('\r', ' ').replace('\n', ' '),
    }
    params = [('request', p) for p in s.get('inputs', [])] + \
             [('response', p) for p in s.get('outputs', [])]
    if not params:
        yield dict(base)
        return
    for i, (direction, p) in enumerate(params):
        bits = p.get('bits')
        pres = p.get('presentation') or {}
        enums = '; '.join(f"{sc['enum_low']}={sc['text']}"
                          for sc in pres.get('scales', []) if sc.get('text'))
        row = dict(base)
        row.update({
            'direction': direction,
            'param_index': i,
            'byte': p['bitpos'] // 8,
            'bit': p['bitpos'] % 8,
            'size_bits': '' if bits is None else bits,
            'size_bytes': (bits // 8) if bits and bits % 8 == 0 else '',
            'param': p.get('qualifier') or '',
            'param_name': p.get('name') or '',
            'kind': p.get('kind', ''),
            'presentation': pres.get('qualifier') or '',
            'const_value': const_hex(p),
            'enum_values': enums,
        })
        yield row


def export_csv(cbf_path, csv_path=None, name_filter=None):
    """Parse one CBF and write all services/parameters to CSV. Returns (csv_path, service_count)."""
    import csv
    import os
    cff, ecus = parse(cbf_path)
    if csv_path is None:
        csv_path = os.path.splitext(cbf_path)[0] + '_services.csv'
    count = 0
    # utf-8-sig + ';' so Excel (TR/EU locale) opens it directly with correct characters
    with open(csv_path, 'w', encoding='utf-8-sig', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, delimiter=';')
        w.writeheader()
        for e in ecus:
            for s in e['services']:
                q = s.get('qualifier') or ''
                if name_filter and name_filter.lower() not in q.lower():
                    continue
                count += 1
                for row in service_rows(e['qualifier'], s):
                    w.writerow(row)
    return csv_path, count


def gui_export():
    """Double-click mode: pick one or more CBF files, export each to CSV next to it."""
    import os
    import tkinter as tk
    from tkinter import filedialog, messagebox
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    files = filedialog.askopenfilenames(
        title='CSV olarak dışa aktarılacak CBF dosyalarını seçin',
        filetypes=[('Caesar CBF', '*.cbf *.CBF'), ('Tüm dosyalar', '*.*')])
    if not files:
        root.destroy()
        return
    ok, failed = [], []
    for f in files:
        print(f'Ayrıştırılıyor: {f}')
        try:
            out, n = export_csv(f)
            ok.append(f'{os.path.basename(out)}  ({n} servis)')
            print(f'  -> {out} ({n} servis)')
        except Exception as ex:
            failed.append(f'{os.path.basename(f)}: {ex}')
            print(f'  HATA: {ex}')
    msg = ''
    if ok:
        msg += 'Oluşturulan CSV dosyaları (CBF ile aynı klasörde):\n\n' + '\n'.join(ok)
    if failed:
        msg += ('\n\n' if msg else '') + 'Hata verenler:\n\n' + '\n'.join(failed)
    (messagebox.showwarning if failed else messagebox.showinfo)('CaesarStruct', msg, parent=root)
    root.destroy()


def main():
    # Windows consoles (cp1252/cp857) cannot encode every CBF string.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors='replace')
        except AttributeError:
            pass

    # Double-click / no arguments: file picker + CSV export
    if len(sys.argv) == 1:
        gui_export()
        return

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cbf', nargs='+', help='one or more CBF files')
    ap.add_argument('-f', '--filter', help='substring filter on service qualifier (case-insensitive)')
    ap.add_argument('--outputs', action='store_true', help='also print response parameters')
    ap.add_argument('--json', help='write parsed services to JSON file (single CBF only)')
    ap.add_argument('--csv', action='store_true',
                    help='export every given CBF to <name>_services.csv next to it instead of printing')
    a = ap.parse_args()

    if a.csv:
        for f in a.cbf:
            out, n = export_csv(f, name_filter=a.filter)
            print(f'{f} -> {out} ({n} services)')
        return

    for path in a.cbf:
        cff, ecus = parse(path)
        sel = []
        for e in ecus:
            print(f"ECU {e['qualifier']}  (caesar {cff['caesar_version']}, {len(e['services'])} services)")
            for s in e['services']:
                q = s.get('qualifier') or ''
                if a.filter and a.filter.lower() not in q.lower():
                    continue
                sel.append(s)
                if 'request' not in s:
                    print('  ' + q)
                    continue
                print(f"\n  {q}  [{s['type']}]  security={s['security_access_level']}")
                if s.get('name'):
                    print(f"    name: {s['name']}")
                print(f"    request template ({s['request_len']} B): {s['request']}")
                for p in s['inputs']:
                    print(fmt_prep(p))
                if a.outputs and s['outputs']:
                    print('    -- response --')
                    for p in s['outputs']:
                        print(fmt_prep(p))
        if a.json:
            with open(a.json, 'w', encoding='utf-8') as fh:
                json.dump(sel, fh, ensure_ascii=False, indent=1, default=str)


if __name__ == '__main__':
    main()
