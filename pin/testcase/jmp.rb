require 'metasm'


pe = Metasm::PE.assemble Metasm::Ia32.new, <<EOS
.entrypoint
  push user32
  call loadlibrary
	push msgbox
	push eax
	call getprocaddress

	push 0
	push title
  push message
  push 0
  
  push $+7
	jmp eax

  xor eax, eax
  ret

.import 'kernel32' GetProcAddress getprocaddress
.import 'kernel32' LoadLibraryA loadlibrary

.data
	msgbox db 'MessageBoxA', 0
	user32 db 'user32.dll', 0
  message db 'Hello EAX!', 0
  title db 'jmp eax', 0
EOS

pe.encode_file 'jmp.exe'
