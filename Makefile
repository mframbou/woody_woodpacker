run:
	@echo building container
	docker build -t mframbouandoronda ./
	@echo starting container
	docker run -v "$(PWD)/srcs":/mframbouandoronda -it mframbouandoronda