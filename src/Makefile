RM := rm -rf

LIBS := -lntl
OPTIMIZATIONS := 

# Source, objects and dependencies 
CPP_SRCS += \
./LWEKeypair.cpp \
./LWEPrivateKey.cpp \
./LWEPublicKey.cpp \
./LWE.cpp \
./Parameters.cpp \
./Sampler.cpp \
./main.cpp 

OBJS += \
../obj/LWEKeypair.o \
../obj/LWEPrivateKey.o \
../obj/LWEPublicKey.o \
../obj/LWE.o \
../obj/Parameters.o \
../obj/Sampler.o \
../obj/main.o 

CPP_DEPS += \
../obj/LWEKeypair.d \
../obj/LWEPrivateKey.d \
../obj/LWEPublicKey.d \
../obj/LWE.d \
../obj/Parameters.d \
../obj/Sampler.d \
../obj/main.d 


# Build single objects
../obj/%.o: %.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ $(OPTIMIZATIONS) -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

# All Target
all: ../bin/LWE-Polynomial

# Tool invocations
../bin/LWE-Polynomial: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	g++  -o "../bin/LWE-Polynomial" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(CU_DEPS)$(OBJS)$(C++_DEPS)$(C_DEPS)$(CC_DEPS)$(CPP_DEPS)$(EXECUTABLES)$(CXX_DEPS)$(C_UPPER_DEPS) ../bin/LWE-Polynomial
	-@echo ' '
