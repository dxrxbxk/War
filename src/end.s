global end
;global sign

section .text

;sign:
;	db 0x0, "Famine (c)oded by dxrxbxk - 42424242", 0x0a, 0x0

end:
	; exit
	mov rax, 60
	xor rdi, rdi
	syscall
