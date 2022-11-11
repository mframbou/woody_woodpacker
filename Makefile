run:
	@echo building container
	docker build -t ft_woody ./
	@echo starting container
	docker run -v "$(PWD)/srcs":/ft_woody -it ft_woody