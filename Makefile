bv: bvd bvctl

bv%: bv%.c
	gcc -lpthread -ldl -o $@ $<

%.so: module/%
	cd $< && make

modules: $(patsubst module/%, %.so, $(wildcard module/*))

all: bv modules
