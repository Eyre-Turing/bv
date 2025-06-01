bv: bvd bvctl

bv%: bv%.c
	gcc -ldl -o $@ $<

%.so: module/%
	cd $< && make

modules: $(patsubst module/%, %.so, $(wildcard module/*))

all: bv modules
