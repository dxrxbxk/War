NAME = War

src = src/famine.c \
      src/data.c \
      src/map.c \
      src/bss.c \
      src/utils.c \
	  src/text.c \
	  src/pestilence.c \
	  src/war.c 

asm = src/syscall.s \
	  src/decrypt.s \
      src/end.s

obj = $(src:.c=.o) $(asm:.s=.o)

cflags = -fpic -nostdlib -I./inc
# -no-pie -fno-stack-protector -fno-builtin 
#-fpic -fno-stack-protector -nodefaultlibs -fno-builtin -fno-omit-frame-pointer -pie -static

sflags = -f elf64

ldflags = -nostdlib -z noexecstack 
#-pie -static

.PHONY: all clean fclean re

all: $(NAME)

$(NAME): $(obj)
	gcc -o $(NAME) $(obj) $(ldflags)

src/%.o: src/%.c
	gcc $(cflags) -o $@ -c $< 

src/%.o: src/%.s
	nasm $(sflags) -o $@ $<

clean:
	rm -f $(obj)

fclean: clean
	rm -f $(NAME)

re: fclean all
