#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include "fileManagement.h"
#include "dynamicVectors.h"

static int FILE_CompareString(const void * a, const void * b);

static int FILE_CompareString(const void * a, const void * b)
{
    return strcmp (*(const char **) a, *(const char **) b);
}

static int FILE_CompareStringParameter(const void * a, const void * b);

static int FILE_CompareStringParameter(const void * a, const void * b)
{
    const FILE_StringParameter_DataType * typeA = *(const FILE_StringParameter_DataType **)a;
    const FILE_StringParameter_DataType * typeB = *(const FILE_StringParameter_DataType **)b;
    printf("Comparing  %s with %s",typeA->Name, typeB->Name);
    return strcmp(typeA->Name, typeB->Name);
}

/* Check if inode is a directory */
int FILE_IsDirectory(char *DirectoryPath)
{
    struct stat sb;
    if (stat(DirectoryPath, &sb) == 0 && S_ISDIR(sb.st_mode))
        {
        return 1;
        }
    else
        {
        return 0;
        }
    
    return 0;
}

long int FILE_GetAvailableSpace(const char* path)
{
    struct statvfs stat;

    if (statvfs(path, &stat) != 0)
    {
        // error happens, just quits here
        return -1;
    }

    // the available size is f_bsize * f_bavail
    return stat.f_bsize * stat.f_bavail;
}

/* Get the file size */
int FILE_GetFileSize(FILE *TheFilePointer)
{
    int Prev = 0, TheFileSize = 0;
    Prev = ftell(TheFilePointer);
    fseek(TheFilePointer, 0L, SEEK_END);
    TheFileSize = ftell(TheFilePointer);
    fseek(TheFilePointer, Prev, SEEK_SET);
    return TheFileSize;
}

int FILE_GetFileSizeFromPath(char *TheFileName)
{
    if (FILE_IsFile(TheFileName) == 1)
    {
        FILE *TheFilePointer;
        TheFilePointer = fopen(TheFileName, "rb");
        int Prev = 0, TheFileSize = 0;
        Prev = ftell(TheFilePointer);
        fseek(TheFilePointer, 0L, SEEK_END);
        TheFileSize = ftell(TheFilePointer);
        fseek(TheFilePointer, Prev, SEEK_SET);
        fclose(TheFilePointer);
        return TheFileSize;
    }
    else
    {
        return 0;
    }
}

/* Check if a file is valid */
int FILE_IsFile(const char *TheFileName)
{
  FILE *TheFile;
  TheFile = fopen(TheFileName, "rb");

  if (TheFile)
    {
        fclose(TheFile);
        return 1;
    }

  return 0;
}

void FILE_GetDirectoryInodeList(char * DirectoryInodeName, char *** InodeList, int * FilesandFolders, int Recursive)
	{
	int FileAndFolderIndex = *FilesandFolders;

	//Allocate the array for the 1st time
	if (*InodeList == NULL)
		{
		(*InodeList) = (char **) malloc(sizeof(char *) * (1));
		}

	DIR *TheDirectory;
	struct dirent *dir;
	TheDirectory = opendir(DirectoryInodeName);

	if (TheDirectory)
		{
		 while ((dir = readdir(TheDirectory)) != NULL)
		 	 {
				if ( dir->d_name[0] != '.' )
					{
					//Set the row to needed size
					int ReallocSize = sizeof(char *) * (FileAndFolderIndex+1)+1;
					(*InodeList) = (char ** ) realloc((*InodeList), ReallocSize );
					int nsize = strlen(dir->d_name) * sizeof(char) + strlen(DirectoryInodeName) * sizeof(char) + 2;
					//Allocate the path string size
					(*InodeList)[FileAndFolderIndex]  = (char *) malloc (  nsize );
					strcpy((*InodeList)[FileAndFolderIndex], DirectoryInodeName );
					strcat((*InodeList)[FileAndFolderIndex], "/" );
					strcat((*InodeList)[FileAndFolderIndex], dir->d_name );
					(*InodeList)[FileAndFolderIndex][ strlen(dir->d_name)  + strlen(DirectoryInodeName) + 1 ] = '\0';
					(*FilesandFolders)++;
					FileAndFolderIndex++;

					if ( Recursive == 1 && FILE_IsDirectory((*InodeList)[*FilesandFolders-1]) == 1  )
						{
						FILE_GetDirectoryInodeList ( (*InodeList)[FileAndFolderIndex-1], InodeList, FilesandFolders, Recursive );
						FileAndFolderIndex = (*FilesandFolders);
						}
				 }
		 	 }
		 closedir(TheDirectory);
		}

	qsort ((*InodeList), *FilesandFolders, sizeof (const char *), FILE_CompareString);
	}

int FILE_GetStringFromFile(char * filename, char **file_content)
	{
	int file_size = 0;
	int c, count;

	if (FILE_IsFile(filename) == 0)
		{
		return 0;
		}

	FILE *file = fopen(filename, "rb");

	if (file == NULL)
		{
		fclose(file);
		return 0;
		}

	file_size = FILE_GetFileSize(file);

	count = 0;
	*file_content  = (char *) malloc(file_size * sizeof(char) + 1);

	while ((c = fgetc(file)) != EOF)
		{
		(*file_content)[count++] = (char) c;
		}
	(*file_content)[count] = '\0';
	fclose(file);
	return (count);
	}

void FILE_ReadStringParameters(char * filename, DYNV_VectorGenericDataType *ParametersVector)
	{
	FILE *File;
	char Line[FILE_MAX_LINE_LENGHT];
	int i;
	int c;
	char FirstChar = 0;
	char SeparatorChar = 0;
	char ParameterChar = 0;
	int BufferNameCursor = 0;
	int BufferValueCursor = 0;
	FILE_StringParameter_DataType TheParameter;

	memset (TheParameter.Name, 0, FILE_MAX_PAR_VAR_SIZE);
	memset (TheParameter.Value, 0, FILE_MAX_PAR_VAR_SIZE);

	File = fopen(filename, "r");
	if(File == NULL)
        {
            printf("error while opening file %s", filename);
        }
	else
		{
		printf("Parameter initializing from file %s", filename);

		while(fgets(Line, FILE_MAX_LINE_LENGHT, File) != NULL)
			{
			//printf("LINE: %s", Line);
			i = 0;

			while (i<FILE_MAX_LINE_LENGHT)
				{
				c = Line[i++];
				if (((char) c == ' ' && FirstChar != '#') || (char) c == '\r' || (c == 9 && FirstChar != '#' ) || (c == 10) || (c == 13))
					{
					continue;
					}

				if ((char) c == '\0' )
					{
				  if ((FirstChar != '#' && FirstChar != '=' && FirstChar != 0 ) && SeparatorChar == '=' && ParameterChar != 0 )
				  	{
				  	TheParameter.Name[BufferNameCursor] = '\0';
				  	TheParameter.Value[BufferValueCursor] = '\0';
				  	printf("Adding name: %s value: %s", TheParameter.Name, TheParameter.Value);
				  	//printf("TheParameter.Name[0] = %d", TheParameter.Name[0]);

				  	ParametersVector->PushBack(ParametersVector, &TheParameter, sizeof(FILE_StringParameter_DataType));
						BufferNameCursor = 0;
						BufferValueCursor = 0;
						memset (TheParameter.Name, 0, FILE_MAX_PAR_VAR_SIZE);
						memset (TheParameter.Value, 0, FILE_MAX_PAR_VAR_SIZE);
				    }

					FirstChar = 0;
					SeparatorChar = 0;
					ParameterChar = 0;

					if ((char) c == '\0')
						{
						break;
						}
				   }
				   else
				   	{
				  	 //printf("Checking chars");

						//first char, parameter name
						if (FirstChar == 0)
							{
							FirstChar = (char) c;
							//printf("FirstChar = %c", FirstChar);
							}
						else if (FirstChar != 0 && SeparatorChar == 0 && (char) c == '=')
							{
							SeparatorChar = (char) c;
							//printf("SeparatorChar = %c", SeparatorChar);
							}
						else if (FirstChar != 0 && SeparatorChar != 0 && ParameterChar == 0)
							{
							ParameterChar = (char) c;
							//printf("ParameterChar = %c", ParameterChar);
							}

						//Get the parameter name
						if ( FirstChar != '#' && FirstChar != 0 && SeparatorChar == 0 && BufferNameCursor < FILE_MAX_PAR_VAR_SIZE )
							if(BufferNameCursor < FILE_MAX_PAR_VAR_SIZE)
								TheParameter.Name[BufferNameCursor++] = (char) c;

						//Get the parameter value
						if ( FirstChar != '#' && FirstChar != 0 && SeparatorChar != 0 && ParameterChar != 0 && BufferValueCursor < FILE_MAX_PAR_VAR_SIZE )
							if(BufferValueCursor < FILE_MAX_PAR_VAR_SIZE)
								TheParameter.Value[BufferValueCursor++] = (char) c;
				        }
				    }
				}

			fclose(File);
			}

	printf("ParametersVector->Size %d", ParametersVector->Size);

	for (i = 0; i < ParametersVector->Size; i++)
		{
		printf("ParametersVector->Data[%d])->Name = %s",i, ((FILE_StringParameter_DataType *)ParametersVector->Data[i])->Name);
		}

	qsort(ParametersVector->Data, ParametersVector->Size, sizeof(void *), FILE_CompareStringParameter);

	printf("Sorted");
	for (i = 0; i < ParametersVector->Size; i++)
		{
		printf("ParametersVector->Data[%d])->Name = %s",i, ((FILE_StringParameter_DataType *)ParametersVector->Data[i])->Name);
		}

	}

int FILE_StringParametersLinearySearch(DYNV_VectorGenericDataType *TheVectorGeneric, void * name)
	{
	int i;
	for(i=0; i<TheVectorGeneric->Size; i++)
		{
		if(strcmp(((FILE_StringParameter_DataType *)TheVectorGeneric->Data[i])->Name, (char *) name) == 0)
			{
			return i;
			}
		}
	return -1;
	}

int FILE_StringParametersBinarySearch(DYNV_VectorGenericDataType *TheVectorGeneric, void * Needle)
	{

	long long int CompareResult;

	if (TheVectorGeneric->Size <= 0)
		{
		return -1;
		}

	int littler = 0;
	int last = TheVectorGeneric->Size - 1;
	int middle = (littler + last) / 2;

	while (littler <= last)
		{
		CompareResult = strcmp(((FILE_StringParameter_DataType *)TheVectorGeneric->Data[middle])->Name, Needle);
		//printf("CompareResult = %d.\n", CompareResult);

		if ((CompareResult == 0))
			{
			//printf("%d found at location %d.\n", Needle, middle);
			return middle;
			}
			else if (CompareResult < 0)
			{
			littler = middle + 1;
			//printf("Needle bigger than middle  at %d .\n", middle);
			}
		else
			{
			last = middle - 1;
			//printf("Needle lower than middle  at %d.\n", middle);
			}

			middle = (littler + last)/2;
			}

	if (littler > last)
		{
		//printf("Not found! %d is not present in the list.\n", Needle);
		return -1;
		}

  return -1;

	}

char * FILE_GetFilenameFromPath(char * FileName)
{
	int i = 0;
	char * TheStr = FileName;
	for (i = 0; i< strlen(FileName); i++)
		{
		if (FileName[i] == '/' || FileName[i] == '\\')
		{
			TheStr = FileName+i+1;
			}
		}

	return TheStr;
}

char * FILE_GetListPermissionsString(char *file) {
    struct stat st;
    char *modeval = malloc(sizeof(char) * 10 + 1);
    if(stat(file, &st) == 0) {
        mode_t perm = st.st_mode;
        
    modeval[0] = (S_ISDIR(st.st_mode)) ? 'd' : '-';
    modeval[0] = (perm & S_IFMT == S_IFLNK) ? 'L' : modeval[0];
    modeval[1] = (perm & S_IRUSR) ? 'r' : '-';
    modeval[2] = (perm & S_IWUSR) ? 'w' : '-';
    modeval[3] = (perm & S_IXUSR) ? 'x' : '-';
    modeval[4] = (perm & S_IRGRP) ? 'r' : '-';
    modeval[5] = (perm & S_IWGRP) ? 'w' : '-';
    modeval[6] = (perm & S_IXGRP) ? 'x' : '-';
    modeval[7] = (perm & S_IROTH) ? 'r' : '-';
    modeval[8] = (perm & S_IWOTH) ? 'w' : '-';
    modeval[9] = (perm & S_IXOTH) ? 'x' : '-';
    modeval[10] = '\0';
    //printf("\n\n");   
    //printf( (S_ISDIR(st.st_mode)) ? "d" : "-");
   // printf( (fileStat.st_mode & S_IRUSR) ? "r" : "-");
   // printf( (fileStat.st_mode & S_IWUSR) ? "w" : "-");
   // printf( (fileStat.st_mode & S_IXUSR) ? "x" : "-");
   // printf( (fileStat.st_mode & S_IRGRP) ? "r" : "-");
   // printf( (fileStat.st_mode & S_IWGRP) ? "w" : "-");
   // printf( (fileStat.st_mode & S_IXGRP) ? "x" : "-");
   // printf( (fileStat.st_mode & S_IROTH) ? "r" : "-");
   // printf( (fileStat.st_mode & S_IWOTH) ? "w" : "-");
   // printf( (fileStat.st_mode & S_IXOTH) ? "x" : "-");
        return modeval;     
    }
    else {
        return 0;
    }   
}

char * FILE_GetOwner(char *fileName)
{
    char *toReturn;
    struct stat info;
    stat(fileName, &info);  // Error check omitted
    struct passwd *pw = getpwuid(info.st_uid);
    //struct group  *gr = getgrgid(info.st_gid);
    
    if (pw->pw_name == 0)
        return 0;
        
    toReturn = (char *) malloc (strlen(pw->pw_name) + 1);
    strcpy(toReturn, pw->pw_name);
    
    return toReturn;
}

char * FILE_GetGroupOwner(char *fileName)
{
    char *toReturn;
    struct stat info;
    stat(fileName, &info);  // Error check omitted
    //struct passwd *pw = getpwuid(info.st_uid);
    struct group  *gr = getgrgid(info.st_gid);
    
    if (gr->gr_name == 0)
        return 0;
    
    toReturn = (char *) malloc (strlen(gr->gr_name) + 1);
    strcpy(toReturn, gr->gr_name);
    
    return toReturn;
}


time_t FILE_GetLastModifiedData(char *path)
{
    struct stat statbuf;
    if (stat(path, &statbuf) == -1) {
        perror(path);
        exit(1);
    }
    return statbuf.st_mtime;
}

char *FILE_AppendToString(char ** sourceString, char *theString)
{
	int theNewSize = strlen(*sourceString) + strlen(theString);
	*sourceString = realloc(*sourceString, theNewSize + 10);
	strcat(*sourceString, theString);
	(*sourceString)[theNewSize] = '\0';
}

char *FILE_DirectoryToParent(char ** sourceString)
{
         //printf("\n");
        int i = 0, theLastSlash = -1, strLen = 0;
        
        strLen = strlen(*sourceString);
        //printf("\nstrLen = %d", strLen);
        
        for (i = 0; i < strLen; i++)
        {
            
            //printf("%c", (*sourceString)[i]);
            
            if ( (*sourceString)[i] == '/')
            {
                theLastSlash = i;
                //printf("\n theLastSlash = %d", theLastSlash);
            }

        }

        if (theLastSlash > -1)
        {
            int theNewSize = theLastSlash;
            if (theLastSlash == 0)
            {
                theNewSize = 1;
            }
            *sourceString = realloc(*sourceString, theNewSize);
            (*sourceString)[theNewSize] = '\0';

        }
}