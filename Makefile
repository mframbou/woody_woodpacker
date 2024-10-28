SRCS = $(wildcard srcs/*.c)

OBJS = $(SRCS:.c=.o)

LIBFT_FOLDER = ./srcs/libft
LIBFT = $(LIBFT_FOLDER)/libft.a

NAME = woody_woodpacker

CC = gcc

CFLAGS =  # -Wall -Wextra -Werror

SHELL = zsh

AQUA = \033[0;96m
AQUA_BOLD = \033[1;96m

PURPLE = \033[0;95m
PURPLE_BOLD = \033[1;95m

GREEN = \033[0;92m
GREEN_BOLD = \033[1;92m
GREEN_UNDRLINE = \033[4;32m

RED = \033[0;91m
IRED = \033[0;31m
RED_BOLD = \033[1;91m

SAME_LINE = \033[0G\033[2K

RESET = \033[0m

%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo -n "$(SAME_LINE)$(AQUA)Compiling $(AQUA_BOLD)$<$(RESET)"

# need .h files so will recompile when header changes
$(NAME):	$(LIBFT) $(OBJS)
	@echo
	@echo "$(PURPLE)Linking ($(PURPLE)*.o) into $(PURPLE_BOLD)$(NAME)$(RESET)"
# https://stackoverflow.com/questions/6016815/how-to-include-needed-c-library-using-gcc
# https://stackoverflow.com/questions/1517138/trying-to-include-a-library-but-keep-getting-undefined-reference-to-messages
	@$(CC) $(CFLAGS) $(OBJS) -lft -L$(LIBFT_FOLDER) -o $(NAME)
	@echo "$(GREEN_BOLD)Done compiling $(GREEN_UNDERLINE)$(NAME)$(RESET)"

all:		$(NAME)

$(LIBFT):
	@$(MAKE) -C $(LIBFT_FOLDER) NO_FT_MALLOC=1 NO_GNL=1

clean:
	@rm -f $(OBJS)
	@echo "$(RED)Removing $(IRED)*.o$(RESET)"
	@make -C $(LIBFT_FOLDER) clean

fclean:		clean
	@rm -f $(NAME)
	@echo "$(RED)Removing $(IRED)$(NAME)$(RESET)"
	@make -C $(LIBFT_FOLDER) fclean

re:			fclean all

# Re only for exec not dependencies
rexec:
	@rm -f $(OBJS)
	@echo "$(RED)Removing $(IRED)*.o$(RESET)"
	@rm -f $(NAME)
	@echo "$(RED)Removing $(IRED)$(NAME)$(RESET)"
	@$(MAKE)

.PHONY:	all clean fclean re