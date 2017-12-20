#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
/*------------------------------------------------------------*/
#define RULE_LINE_LEN		4096
#define MAX_CONTENT		2048
#define HEADER_LEN		54
#define MAX_RULE		8192
#define UNUSED(x)		(void)x

/* content & regular expression g_vars */
//static char **g_pcre_string;
//static int *g_pcre_len;
char **g_content;
int *g_content_len;
char *null_payload;
static const int packet_size = 1514;

/* Function headers */
int readSnortRules(const char *);
void cleanupRules(int);
/*------------------------------------------------------------*/
int
readSnortRules(const char *filename)
{
	FILE *fp;
	char *p, *result, *saveptr, *temp, *end, *pcre[MAX_RULE];
	char line[RULE_LINE_LEN], new_content[MAX_CONTENT], ox[2];
	int num_rule, i, j, loc, len_temp, flag, hex_num, rule_dec;
	char hex[6] = "0x";

	/* set null_payload */
	null_payload = calloc(1, packet_size);
	if (null_payload == NULL) {
		fprintf(stderr, "Not enough memory to initialize null payload!\n");
		exit(EXIT_FAILURE);
	}
	
	loc = num_rule = flag = rule_dec = 0;
	/* calculate number of rules */
	if ((fp = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "[%s:%d]] File %s failed to open!\n",
			__FUNCTION__, __LINE__, filename);
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (*line == '#' || *line == '\0')
			continue;
		else
			num_rule++;
	}

	/* 
	 * rewind. I know this is inefficent, but will improve
	 * on this in the next iteration
	 */
	rewind(fp);

	/* for content */
	if ((p = (char *)calloc(/*4 * */sizeof(char),
				MAX_CONTENT * num_rule)) == NULL) {
		fprintf(stderr, "[%s:%d] Memory allocation for "
			"contents failed\n", __FUNCTION__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if ((g_content = (char **)calloc(num_rule,
					 sizeof(char *))) == NULL) {
		fprintf(stderr, "[%s:%d] Malloc for content failed\n",
			__FUNCTION__, __LINE__);
		exit(EXIT_FAILURE);
	}
	
	if ((g_content_len = (int *)calloc(num_rule,
					   sizeof(int))) == NULL) {
		fprintf(stderr, "[%s:%d] Malloc for g_content_len failed\n",
			__FUNCTION__, __LINE__);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < num_rule; i++) {
		if (fgets(line, sizeof(line), fp) == NULL) {
			fprintf(stderr, "[%s:%d] Reading %dth rule failed\n",
				__FUNCTION__, __LINE__, i);
			exit(EXIT_FAILURE);
		}

		result = strstr(line, "content:");
		if (result == NULL) {
			strcpy(new_content, "No_Content");
			loc = strlen(new_content);
		} else {
			result = strtok_r(result, "\"", &saveptr);
			result = strtok_r(NULL, "\"", &saveptr);

			if ((temp = strdup(result)) == NULL) {
				fprintf(stderr, "[%s:%d] Reading content failed\n",
					__FUNCTION__, __LINE__);
				exit(EXIT_FAILURE);
			}
			len_temp = strlen(temp);
			memset(new_content, 0, MAX_CONTENT);
			for (j = 0; j < len_temp; j++) {
				if (temp[j] == '|') {
					if (flag == false) {
						flag = true;
						continue;
					} else if (flag == true) {
						flag = false;
						continue;
					}
				}
				if (flag == true) {
					if (temp[j] == ' ')
						continue;

					memset(hex, 0, 5);
					strcpy(hex, "0x");

					ox[0] = temp[j];
					ox[1] = temp[j + 1];

					strncat(hex, ox, 2);
					sscanf(hex, "0x%2X", &hex_num);
					new_content[loc] = hex_num;

					loc++;
					j++;
				} else if (flag == false) {
					new_content[loc] = temp[j];
					loc++;
				}
			}
			free(temp);
		}

		if (loc + 1 <= packet_size - HEADER_LEN) {
			memcpy(p, new_content, loc + 1);
			g_content[i - rule_dec] = p;
			g_content_len[i - rule_dec] = loc + 1;
			p += (loc + 1);
		} else
			rule_dec++;

		flag = false;
		loc = 0;
	}

	/* rewind again */
	rewind(fp);
#if 0
	for (i = 0; i < num_rule; i++) {
		if (fgets(line, sizeof(line), fp) == NULL) {
			fprintf(stderr, "[%s:%d]: Reading %dth rule failed\n",
				__FUNCTION__, __LINE__, i);
			exit(EXIT_FAILURE);
		}

		result = strstr(line, "pcre:");
		if (result == NULL)
			continue;
		end = strstr(result, "\"");
		result = end + 1;
		end = strstr(result, "\"; ");
		end[0] = '\0';
		
		if ((temp = strdup(result)) == NULL) {
			fprintf(stderr, "[%s:%d] Reading PCRE failed\n",
				__FUNCTION__, __LINE__);
			exit(EXIT_FAILURE);
		}
		pcre[i] = temp;
	}
#endif	
	fclose(fp);

#ifdef TEST_SNORT_RULE_PARSING
	printf("rule_dec: %d\n", rule_dec);
	for(i = 0; i < num_rule - rule_dec; i++) {
		fprintf(stdout, "%d: content: ", i);
		for (j = 0; j < g_content_len[i]; j++)
			fprintf(stdout, "0x%02X ", g_content[i][j]);
		fprintf(stdout, "pcre: %s\n", pcre[i]);
	}
#else
	UNUSED(pcre);
#endif
	UNUSED(end);
	
	return num_rule - rule_dec;
}
/*------------------------------------------------------------*/
void
cleanupRules(int num_rules)
{
	/* freeing up all resources allocated */
	free(null_payload);
	free(g_content_len);
	free(g_content);
}
/*------------------------------------------------------------*/
#ifdef TEST_SNORT_RULE_PARSING
int
main(int argc, char **argv)
{
	int num_rules;
	
	if (argc != 2) {
		fprintf(stderr, "[%s:%d]Usage: %s <snort_rule_file>\n",
			__FUNCTION__, __LINE__, argv[0]);
		exit(EXIT_FAILURE);
	}
	
	num_rules = readSnortRules(argv[1]);
	if (num_rules <= 0) {
		fprintf(stderr, "[%s:%d] There are no rules in the file\n",
			__FUNCTION__, __LINE__);
		exit(EXIT_FAILURE);
	}

	cleanupRules(num_rules);
	return EXIT_SUCCESS;
}
#endif
/*------------------------------------------------------------*/
