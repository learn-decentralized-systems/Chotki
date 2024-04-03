package rdx 

import (
    "fmt"
)

%%{

machine REPL;
include RDX "rdx.rl";

write data;

action cmd { cmd = string(data[mark[0]:p]); }
action dot {
    rdx.Parent = path
    path.Nested = append(path.Nested, *rdx)
    rdx = &RDX{}
}
action path { 
    rdx.Parent = path
    path.Nested = append(path.Nested, *rdx)
    rdx = &RDX{}
}

PATH = token ([\.\/] %dot token)* ; 
ws = space;

command = [a-z]+;

main :=
    ws*
    command >b %cmd
    (ws+ PATH %path)? 
    (ws+ RDX)? 
    ws*;

}%%

func ParseREPL(data []byte) (cmd string, path *RDX, rdx *RDX, err error) {

    var mark [RdxMaxNesting]int
    nest, cs, p, pe, eof := 0, 0, 0, len(data), len(data)

    rdx = &RDX{}
    path = &RDX{RdxType:RdxPath}

    %%write init;
    %%write exec;

    if cs < REPL_first_final { 
        err = fmt.Errorf("command parsing failed at pos %d", p)
    }

    return

}