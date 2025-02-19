bits 64
default rel

section .text
    global _start
    %define PROT_READ  0x1
    %define PROT_WRITE 0x2
    %define PROT_EXEC  0x4

signature:
    db "Famine (c)oded by dxrxbxk - 42424242", 0x0a, 0

;/* program that change de signature at runtime */
_start:
	;/* open the file */
	mov rax, 2
	mov rdi, filename
	mov rsi, 2
	mov rdx, 0
	syscall

	;/* read the file */
	mov rdi, rax
	mov rsi, buffer
	mov rdx, 64
	mov rax, 0
	syscall

	;/* change the signature */
	mov rsi, signature
	mov rdi, buffer
	mov rcx, 64
	rep movsb

	;/* write the file */
	mov rax, 1
	mov rdi, rax
	mov rsi, buffer
	mov rdx, 64
	syscall

	;/* close the file */
	mov rax, 3
	mov rdi, rax
	syscall

	;/* exit */
	mov rax, 60
	xor rdi, rdi
	syscall

