EXECBIN = one_thr_proxy
CC = clang
CFLAGS = -std=gnu11 -O0 -Wall -Werror -Wshadow -Wextra
LIB_FLAGS =  -L/usr/local/Cellar/openssl@1.1/1.1.1m/lib -lssl -lcrypto
INCL_FLAG =  $(patsubst %, -I %, $(IDIR))

ODIR = bin
IDIR = src/inc /usr/local/Cellar/openssl@1.1/1.1.1m/include
SDIR = src
XDIR = bin

TDIR = src/tests
_TEST_OBJS = proxymain.o http_helper.o http_module.o tcp_module.o custom_regex.o input_verify.o tls_client.o site_filter.o
TEST_OBJS = $(patsubst %, $(ODIR)/%, $(_TEST_OBJS))
TESTBIN = myproxy


_OBJS = tls_client.o
OBJS = $(patsubst %, $(ODIR)/%, $(_OBJS))

.PHONY: all
all: $(XDIR)/$(TESTBIN)

$(XDIR)/$(TESTBIN): $(TEST_OBJS)
	$(CC) $^  $(LIB_FLAGS) -g -lpthread -o $@


$(XDIR)/$(EXECBIN): $(OBJS)
	$(CC) $^  $(LIB_FLAGS) -o $@

$(ODIR)/%.o: $(SDIR)/%.c
	$(CC) $(CFLAGS) $(INCL_FLAG) -g -c $< -o $@

$(ODIR)/%.o: $(TDIR)/%.c
	$(CC) $(CFLAGS) $(INCL_FLAG) -g -c $< -o $@
.PHONY: clean
clean: 
	rm -f $(ODIR)/*.o $(XDIR)/*

.PHONY: check
check: $(XDIR)/$(EXECBIN)
	valgrind -v --undef-value-errors=no --leak-check=full ./$^

