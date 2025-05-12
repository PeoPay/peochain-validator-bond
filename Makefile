.PHONY: setup dev test build clean

setup:
	rustup update
	cargo install cargo-watch
	npm install

dev:
	cargo watch -x run &
	npm run dev

test:
	cargo test
	npm test

build:
	cargo build --release
	npm run build

clean:
	cargo clean
	npm run clean
