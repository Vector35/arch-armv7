all: parse.py

parse.py: pcode.ebnf
	grako --name pcode pcode.ebnf -o parse.py

clean:
	rm parse.py *.pyc
