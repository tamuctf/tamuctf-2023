NAME := shmooving-2

dist:
	cargo run --release
	zip -j $(NAME).zip encouragement.txt.enc flag.txt.enc src/main.rs
clean:
	rm -f $(NAME).zip flag.txt.enc encouragement.txt.enc
