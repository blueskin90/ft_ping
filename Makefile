# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: toliver <marvin@42.fr>                     +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2018/09/20 19:50:33 by toliver           #+#    #+#              #
#    Updated: 2022/01/28 14:50:57 by toliver          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #


NAME = ft_ping

INCLUDES = -I includes\
		   -I ./libs/libft/includes\
		   -I ./libs/ftprintf/includes

FLAGS = -Wall -Wextra -Werror -g3

OBJS = $(addprefix objs/, $(addsuffix .o, \
			$(addprefix ping/, \
				main \
				) \
			$(addprefix parsing/, \
				parsing \
				) \
		)) 

CC = gcc

HEADERS = ./includes/ft_ping.h

all: $(NAME)

$(NAME): objs $(OBJS) $(HEADERS)
	@printf "\033[92m\033[1:32mCompiling -------------> \033[91m$(NAME)\033[0m:\033[0m%-16s\033[32m[✔]\033[0m\n"
	@$(CC) $(FLAGS) $(OBJS) $(INCLUDES) -o $(NAME) $(LIBS) 

objs/%.o: srcs/%.c
	@printf  "\033[1:92mCompiling $(NAME)\033[0m %-31s\033[32m[$<]\033[0m\n" ""
	@$(CC) -o $@ -c $< $(FLAGS) -fPIC $(INCLUDES)
	@printf "\033[A\033[2K"

objs:
	@mkdir -p objs/ping
	@mkdir -p objs/parsing

clean:
	@printf  "\033[1:32mCleaning object files -> \033[91m$(NAME)\033[0m\033[1:32m:\033[0m%-16s\033[32m[✔]\033[0m\n"
	@rm -rf objs

fclean: clean
	@printf  "\033[1:32mCleaning binary -------> \033[91m$(NAME)\033[0m\033[1:32m:\033[0m%-16s\033[32m[✔]\033[0m\n"
	@	rm -f $(NAME)
re:
	@$(MAKE) fclean
	@$(MAKE)
