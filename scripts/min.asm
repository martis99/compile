section .text
	global _start

_start:
	xor rdi, rdi
	mov rax, 60
	syscall
