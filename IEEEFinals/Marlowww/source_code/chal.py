#!/usr/bin/env python3

import os
import sys


here = os.path.dirname(os.path.abspath(__file__))


candidates = [
    here,                              
    os.path.join(here, "domato-src"),  
    os.path.join(here, "domato"),      
    os.path.join(here, "ieeectf"),     
    "/srv/domato",                     
    "/srv/domato/domato-src",          
    "/opt/domato",                     
]

for p in candidates:
    if p and os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)



if os.path.isdir(os.path.join(here, "domato")):
    parent = here
    if parent not in sys.path:
        sys.path.insert(0, parent)



try:
    import resource
except Exception:
    resource = None


try:
    from grammar import Grammar
except Exception as e:
    # Helpful diagnostic if import still fails
    sys.stderr.write("Failed to import 'grammar' module. sys.path:\n")
    for idx, p in enumerate(sys.path[:12]):
        sys.stderr.write(f"  {idx}: {p}\n")
    sys.stderr.write(f"Import error: {e}\n")
    raise

def set_limits():

    if resource is None:
        return
    mem = os.getenv("JAIL_MEM")
    if mem:
        try:
            mul = {"K": 1024, "M": 1024**2, "G": 1024**3}
            unit = mem[-1].upper()
            if unit in mul:
                val = int(mem[:-1]) * mul[unit]
            else:
                val = int(mem)

            resource.setrlimit(resource.RLIMIT_AS, (val, val))
        except Exception:
            pass
    t = os.getenv("JAIL_TIME")
    if t:
        try:
            tt = int(t)
            resource.setrlimit(resource.RLIMIT_CPU, (tt, tt))
        except Exception:
            pass

def read_until_eof():

    print("define your own rule >> ")
    lines = []
    for raw in sys.stdin:

        line = raw.rstrip("\n")
        if line == "<EOF>":
            break
        lines.append(line)
    return "\n".join(lines)

def find_template():

    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "ieeectf", "template.html"),
        os.path.join(here, "template.html"),
        "/srv/domato/ieeectf/template.html",
        "/domato/ieeectf/template.html",
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception:
                continue

    return "<html> <script> ieeectf = () => { <ieeectf>}</script><body onload=ieeectf()></body></html>"

def main():
    set_limits()
    your_rule = read_until_eof()

    ieeectf_grammar = Grammar()
    try:
        err = ieeectf_grammar.parse_from_string(your_rule)
    except Exception:

        print("Grammer Parse Error")
        sys.exit(-1)

    if err > 0:
        print("Grammer Parse Error")
        sys.exit(-1)

    try:

        ieeectf_result = ieeectf_grammar._generate_code(1)
    except Exception:
        print("Generation Error")
        sys.exit(-1)

    template = find_template()
    output = template.replace("<ieeectf>", ieeectf_result)

    print("your result >> ")
    print(output)

if __name__ == "__main__":
    main()