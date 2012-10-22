##
## PIN tools makefile for Linux
##
## For Windows instructions, refer to source/tools/nmake.bat and
## source/tools/Nmakefile
## 
## To build the examples in this directory:
##
##   cd source/tools/SimpleExamples
##   make all
## 
## To build and run a specific example (e.g., opcodemix)
##   
##   cd source/tools/SimpleExamples
##   make dir opcodemix.test
##
## To build a specific example without running it (e.g., opcodemix)
##   
##   cd source/tools/SimpleExamples
##   make dir obj-intel64/opcodemix.so
##
## The example above applies to the Intel(R) 64 architecture.
## For the IA-32 architecture, use "obj-ia32" instead of 
## "obj-intel64".
##

##############################################################
#
# Here are some things you might want to configure
#
##############################################################

TARGET_COMPILER?=gnu
ifdef OS
    ifeq (${OS},Windows_NT)
        TARGET_COMPILER=ms
    endif
endif

##############################################################
#
# include *.config files
#
##############################################################

ifeq ($(TARGET_COMPILER),gnu)
    include makefile.gnu.config
    CXXFLAGS ?= -I$(PIN_HOME)/source/tools/InstLib -fomit-frame-pointer -Wall -Werror -Wno-unknown-pragmas $(DBG) $(OPT) -MMD -m32
endif

ifeq ($(TARGET_COMPILER),ms)
    include ../makefile.ms.config
    DBG?=
endif

##############################################################
#
# Tools sets
#
##############################################################

TOOL_ROOTS = malwpin debugtrace

TEST_TOOLS_ROOTS = malwpin debugtrace

TEST_TOOLS = $(TEST_TOOLS_ROOTS:%=%$(PINTOOL_SUFFIX))

TOOLS = $(TOOL_ROOTS:%=$(OBJDIR)%$(PINTOOL_SUFFIX))

##############################################################
#
# build targets
#
##############################################################
all: tools apps
tools: $(OBJDIR) $(TOOLS)
test:  $(OBJDIR) $(TEST_TOOLS:%=%.test)

##############################################################
#
# test rules
#
##############################################################
get_source_location.test : $(OBJDIR)get_source_location$(PINTOOL_SUFFIX) $(OBJDIR)get_source_app get_source_location.tested get_source_location.failed
	$(PIN) -t $< -- ./$(OBJDIR)get_source_app > $<.out 2>&1
	grep -q "get_source_app.cpp:2" $<.out 
	grep -q "get_source_app.cpp:3" $<.out 
	grep -q "get_source_app.cpp:4" $<.out 
	rm get_source_location.failed $<.out


##############################################################
#
# build rules
#
##############################################################
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)%.o : %.cpp
	${CXX} ${COPT} $(CXXFLAGS) ${PIN_CXXFLAGS} ${OUTOPT}$@ $< 

$(TOOLS): $(PIN_LIBNAMES)
$(TOOLS): $(OBJDIR)%$(PINTOOL_SUFFIX) : $(OBJDIR)%.o
	${PIN_LD} ${PIN_LDFLAGS} $(LINK_DEBUG) ${LINK_OUT}$@ $< ${PIN_LPATHS} ${PIN_LIBS} $(DBG)


## cleaning
clean:
	-rm -rf $(OBJDIR) *.out *.log *.tested *.failed *.d *makefile.copy *.exp *.lib

-include *.d


