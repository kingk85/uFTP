#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux
CND_DLIB_EXT=so
CND_CONF=Release
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/ftpCommandElaborate.o \
	${OBJECTDIR}/ftpData.o \
	${OBJECTDIR}/ftpServer.o \
	${OBJECTDIR}/library/configRead.o \
	${OBJECTDIR}/library/dynamicVectors.o \
	${OBJECTDIR}/library/fileManagement.o \
	${OBJECTDIR}/library/logFunctions.o \
	${OBJECTDIR}/uFTP.o


# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/uftp

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/uftp: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.c} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/uftp ${OBJECTFILES} ${LDLIBSOPTIONS}

${OBJECTDIR}/ftpCommandElaborate.o: ftpCommandElaborate.c
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/ftpCommandElaborate.o ftpCommandElaborate.c

${OBJECTDIR}/ftpData.o: ftpData.c
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/ftpData.o ftpData.c

${OBJECTDIR}/ftpServer.o: ftpServer.c
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/ftpServer.o ftpServer.c

${OBJECTDIR}/library/configRead.o: library/configRead.c
	${MKDIR} -p ${OBJECTDIR}/library
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/library/configRead.o library/configRead.c

${OBJECTDIR}/library/dynamicVectors.o: library/dynamicVectors.c
	${MKDIR} -p ${OBJECTDIR}/library
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/library/dynamicVectors.o library/dynamicVectors.c

${OBJECTDIR}/library/fileManagement.o: library/fileManagement.c
	${MKDIR} -p ${OBJECTDIR}/library
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/library/fileManagement.o library/fileManagement.c

${OBJECTDIR}/library/logFunctions.o: library/logFunctions.c
	${MKDIR} -p ${OBJECTDIR}/library
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/library/logFunctions.o library/logFunctions.c

${OBJECTDIR}/uFTP.o: uFTP.c
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.c) -O2 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/uFTP.o uFTP.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
