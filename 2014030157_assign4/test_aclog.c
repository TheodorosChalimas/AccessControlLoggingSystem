#include <stdio.h>
#include <string.h>
#include <sys/fsuid.h>
#include <unistd.h>

int main()
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1",
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7",
			"file_8", "file_9"};


	/* example source code */

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL)
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
	file = fopen("prive1.txt", "r");
	bytes = fwrite("privat", 5, 1, file);
	fclose(file);
	file = fopen("prive2.txt", "r");
	bytes = fwrite("privat", 5, 1, file);
	fclose(file);
	file = fopen("prive3.txt", "r");
	bytes = fwrite("privat", 5, 1, file);
	fclose(file);
	file = fopen("prive4.txt", "r");
	bytes = fwrite("privat", 5, 1, file);
	fclose(file);
	file = fopen("prive5.txt", "r");
	bytes = fwrite("privat", 5, 1, file);
	fclose(file);
	file = fopen("prive6.txt", "r");
	bytes = fwrite("privat", 5, 1, file);
	fclose(file);
	file = fopen("prive7.txt", "r");
	bytes = fwrite("privat", 5, 1, file);
	fclose(file);
	file = fopen("prive8.txt", "r");
	bytes = fwrite("privat", 5, 1, file);
	fclose(file);

}
