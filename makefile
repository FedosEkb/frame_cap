

# $(warning A top-level warning $(notdir $(CURDIR)))  
# FOO := $(warning Right-hand side of a simple variable)bar
# BAZ = $(warning Right-hand side of a recursive variable)boo
# $(warning A target)target: $(warning In a prerequisite list)makefile $(BAZ)
#    $(warning In a command script)
#    ls
# $(BAZ): 


include ./paths
#From file 'paths':
#TOOLS

#TARGET := Name of current directory:
TARGET := $(notdir $(CURDIR))# function notdir cut path to current dir 

SRC_DIR := src  # !NOTE! if you want to add some other dir, put their name here
BUILD_DIR := Debug
DEFINE_FLAGS=

SRC_CPP	:= $(foreach DIR, $(SRC_DIR), $(wildcard $(DIR)/*.cpp))
SRC_C	:= $(foreach DIR, $(SRC_DIR), $(wildcard $(DIR)/*.c))
SRC_ASM	:= $(foreach DIR, $(SRC_DIR), $(wildcard $(DIR)/*.asm))# for feature purpose 
SRC_S	:= $(foreach DIR, $(SRC_DIR), $(wildcard $(DIR)/*.S))# for feature purpose 


OBJECTS :=	$(addprefix $(BUILD_DIR)/, $(SRC_C:.c=.o)) \
			$(addprefix $(BUILD_DIR)/, $(SRC_CPP:.cpp=.o)) \
            $(addprefix $(BUILD_DIR)/, $(SRC_ASM:.asm=.o)) \
            $(addprefix $(BUILD_DIR)/, $(SRC_S:.S=.o))
$(warning OBJECTS $(OBJECTS))  


# CXX := $(TOOLS)riscv64-unknown-elf-g++


# CC := $(TOOLS)riscv64-unknown-elf-gcc

CXX := $(TOOLS)g++
CC := $(TOOLS)gcc

# $(warning A top-level warning $(TOOLS)g++ $(TOOLS)gcc)   			

CXXFLAGS =  $(DEFINE_FLAGS) -O0 -fmessage-length=0 \
            -fsigned-char -ffunction-sections -fdata-sections -g3 \
            -std=gnu++11 -fabi-version=0 \
            -fno-exceptions -fno-rtti -fno-use-cxa-atexit \
			-fno-threadsafe-statics -fno-unwind-tables \
            -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -c -o "$@" "$<"
# NOTE разобратся с парамертами:
# -fno-use-cxa-atexit - как я понимаю это описавает алгоритмы вызова для деструкторов статических объектов!!
# зачем его менять не ясно!

CFLAGS =  -O0 -fmessage-length=0 \
            -fsigned-char -ffunction-sections -fdata-sections -g3 \
            -fabi-version=0 \
            -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -c -o "$@" "$<"
#-fno-threadsafe-statics  удалено по рекомендациям gcc
# command-line option ‘-fno-threadsafe-statics’ is valid for C++/ObjC++ but not for C

ASFLAGS =  -O0 -fmessage-length=0 \
            -fsigned-char -ffunction-sections -fdata-sections  -g3 \
            -x assembler-with-cpp \
            -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -c -o "$@" "$<"

LDFLAGS :=  -O0 -fmessage-length=0 \
            -fsigned-char -ffunction-sections -fdata-sections -g3 \
            -Xlinker --gc-sections \
            -Wl,-Map,"$(BUILD_DIR)/$(TARGET).map" 
            
# parameters was been excluded from LDFLAGS:

LDLIBS := -lc -lpcap


default:  all 
.PHONY: all
all: link


.PHONY: link
link: $(OBJECTS)
	@echo Linking target: $(TARGET).out
	@mkdir -p $(dir $@)
	$(CXX) $(LDFLAGS) -o $(BUILD_DIR)/$(TARGET).out $(OBJECTS) $(LDLIBS)
	
	@echo ""
	@echo "Post-build:"
	@sudo setcap cap_net_raw,cap_net_admin=eip $(BUILD_DIR)/$(TARGET).out
# $(TOOLS)riscv64-unknown-elf-objdump -S "$(BUILD_DIR)/$(TARGET).elf" > "$(TARGET).txt"
# $(TOOLS)riscv64-unknown-elf-objcopy -O verilog "$(BUILD_DIR)/$(TARGET).elf" "$(BUILD_DIR)/$(TARGET).hex"
# @echo ""
# @$(TOOLS)riscv64-unknown-elf-size --format=berkeley "$(BUILD_DIR)/$(TARGET).elf"
# @echo ""
	@echo "Done"


#Compile obj-files and generate dependency info
$(BUILD_DIR)/%.o: %.c
	@echo Building file: "$@"
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS)
	@echo ""


$(BUILD_DIR)/%.o: %.cpp
	@echo Building file: "$@"
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS)
	@echo ""

$(BUILD_DIR)/%.o: %.S
	@echo Building file: "$@"
	@mkdir -p $(dir $@)
	$(CXX) $(ASFLAGS)
	@echo ""

$(BUILD_DIR)/%.o: %.asm
	@echo Building file: "$@"
	@mkdir -p $(dir $@)
	$(CXX) $(ASFLAGS)
	@echo ""

#Include .d files for existing .o files
ifneq ($(strip $(OBJECTS:%.o=%.d)),)
-include $(OBJECTS:%.o=%.d)
endif


.PHONY: clean
clean:
	@echo "Clean..."
	@rm -rf $(BUILD_DIR)/*
