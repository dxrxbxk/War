BITS 64
default rel

global packer_start
global packer_end
global size_to_decrypt
global offset_to_data
global key
global jmp_rel
global data_page_size
global sign
global sign_key

%define PROT_READ   0x1
%define PROT_WRITE  0x2
%define PROT_EXEC   0x4

extern end

packer_start:
	push rdx

	cmp byte [rel key], 0
	je .print

	lea rsi, [rel packer_start]
	add rsi, [rel offset_to_data]
	mov rcx, [rel size_to_decrypt]


	lea rdi, [rel key]
	xor rbx, rbx

.loop:
	cmp rcx, 0
	je .print

	mov al, byte [rdi + rbx]
	xor byte [rsi], al
	
	inc rsi
	dec rcx
	inc rbx

	and rbx, 0x07

	jmp .loop

.string:
	db "....WOODY....", 0x0a, 0x0

.print:
	mov rax, 1
	mov rdi, 1
	lea rsi, [rel .string]
	mov rdx, 15

	syscall

;.mprotect_data:
;;; get addr of packer_start
;	lea rdi, [rel packer_start]
;	add rdi, [rel offset_to_data]
;	and rdi, ~0xfff
;
;	mov rax, 10
;	mov rsi, [rel data_page_size]
;	and rsi, ~0xfff ;remove this shit
;	mov rdx, PROT_READ | PROT_WRITE | PROT_EXEC
;
;	syscall

;.mproctect_text:
;	lea rdi, [rel packer_start]
;	and rdi, ~0xfff
;
;	mov rax, 10
;	mov rsi, 0x1000
;	mov rdx, PROT_READ | PROT_EXEC | PROT_WRITE
;
;	syscall

.exit:
	pop rdx

jmp_rel:
	jmp end

sign:
	db "Famine (c)oded by dxrxbxk - 42424242", 0x0a, 0
;	;db "Famine (c)oded by dxrxbxk", 0x0a, 0
sign_key:
; dec 1 byte
	db 0x0
	

data_page_size:
	dq 0x0

size_to_decrypt:
	dq 0x0

offset_to_data:
	dq 0x0

key:
	dq 0x0

packer_end:
	nop
