// level: hard
// mode: scan
// expect: suspicious-binary
// what: an ELF that asks for an executable stack can run code written to the stack, which shell code needs
// with: parts/h70_execstack_bin
