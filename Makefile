NAME = myFamine

SRCS_DIR = ./srcs/
SRCS_FILES = main.c antidebug.c elfHandling.c utils.c
SRCS = $(addprefix $(SRCS_DIR),$(SRCS_FILES))
OBJS = $(subst .c,.o,$(SRCS_FILES))

HDRS_DIR = ./includes/
HDRS_FILES = famine.h
HDRS = $(addprefix $(HDRS_DIR),$(HDRS_FILES))

CC = gcc
CC_FLAGS = -Wall -Wextra -Werror -lprocps -ldl -g3

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CC_FLAGS) -I $(HDRS_DIR) $(OBJS) -o $@

%.o: $(SRCS_DIR)%.c $(HDRS)
	$(CC) $(CC_FLAGS) -I $(HDRS_DIR) -c $< -o $@

re: fclean all

fclean: clean
	rm -f $(NAME)

clean:
	rm -f $(OBJS)

.PHONY: clean fclean re
