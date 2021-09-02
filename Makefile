all:
	clang -o dns_attack dns_attack.c
clean:
	rm -f dns_attack
