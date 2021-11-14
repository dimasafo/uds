#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <time.h>
#include <pthread.h>


#define HTTP_HEADER_LEN 256
#define HTTP_REQUEST_LEN 256
#define HTTP_METHOD_LEN 6
#define HTTP_URI_LEN 100
#define FILE_NAME_LEN 1000
#define LOG_ENTRY_LEN 1000

#define BIG_CHAR_BUFF_LEN 5000

#define REQ_END 100
#define ERR_NO_URI -100
#define ERR_ENDLESS_URI -101

#define MAX_THREADS 3

char* getLogPath()
{
	static char log_path[FILE_NAME_LEN];
	return log_path;
}

char* getBasePath()
{
	static char base_path[FILE_NAME_LEN];
	return base_path;
}

pthread_mutex_t lock;
pthread_mutex_t lock_access_log;
pthread_t threads[MAX_THREADS];
pthread_t fastFinishedThread;

int get_thread_id_index__unsafe(pthread_t id)
{
	for(int i = 0; i < MAX_THREADS; ++i)
	{
		if(threads[i] == id)
			return i;
	}
	
	return -1;
}

int add_thread_to_list__unsafe(pthread_t id)
{
	int idx = get_thread_id_index__unsafe(id);
	
	if (idx != -1)
		return;
		
	for(int i = 0; i < MAX_THREADS; ++i)
	{
		if(threads[i] == 0)
		{
			threads[i] = id;
			return 1;
		}
	}
	
	return 0;
}

int is_any_thread_in_list__unsafe()
{
	for(int i = 0; i < MAX_THREADS; ++i)
	{
		if(threads[i] != 0)
		{
			return 1;
		}
	}
	
	return 0;
}

void remove_thread_from_list__unsafe(pthread_t id)
{
	int idx = get_thread_id_index__unsafe(id);
	
	if (idx != -1)
		threads[idx] = 0;
}

int log_fstr(const char* log_path, const char* format, ...);



struct http_req {
	char request[HTTP_REQUEST_LEN];
	char method[HTTP_METHOD_LEN];
	char uri[HTTP_URI_LEN];
	char uri_path[HTTP_URI_LEN];
	// uri_params
	// version
	// user_agent
	// server
	// accept
};

void fill_uri_path_by_uri(struct http_req* req)
{
	strncpy(req->uri_path, req->uri, strlen(req->uri));
	
	for(size_t idx = 0; idx < strlen(req->uri_path); ++idx)
	{
		if ((req->uri_path)[idx] == '?')
		{
			(req->uri_path)[idx] = '\0';
			break;
		}
	}
}

int fill_req(char *buf, struct http_req *req) 
{
	log_fstr(getLogPath(), " len=%i ", strlen(buf));

	if (strlen(buf) == 2) {
		// пустая строка (\r\n) означает конец запроса
		return REQ_END;
	}
	char *p, *a, *b;
	// Это строка GET-запроса
	p = strstr(buf, "GET");
	if (p == buf) {
		// Строка запроса должна быть вида
		// GET /dir/ HTTP/1.0
		// GET /dir HTTP/1.1
		// GET /test123?r=123 HTTP/1.1
		// и т.п.
		strncpy(req->request, buf, strlen(buf));
		strncpy(req->method, "GET", strlen("GET"));
		a = strchr(buf, '/');
		if ( a != NULL) { // есть запрашиваемый URI 
			b = strchr(a, ' ');
			if ( b != NULL ) { // конец URI
				strncpy(req->uri, a, b-a);
				// пусть пока URI_PATH - то же, что и URI
				//strncpy(req->uri_path, a, b-a);
				fill_uri_path_by_uri(req);
			} else {
				return ERR_ENDLESS_URI;  
				// тогда это что-то не то
			}
		} else {
			return ERR_NO_URI; 
			// тогда это что-то не то
		}
	}
	
	p = strstr(buf, "exit"); //exit marker
	if (p == buf) {
		strncpy(req->uri_path, "exit", strlen("exit"));
		return REQ_END;
	}

	return 0;	
}




int log_fstr(const char* log_path, const char* format, ...)
{
	char buf[BIG_CHAR_BUFF_LEN];

	va_list args;

	va_start(args, format);
	vsprintf(buf, format, args);
	va_end(args);

	return log_str(log_path, buf);
}

int log_str(char* log_path, const char* str) {
	int fd;
	
	//return 0;
	
	pthread_mutex_lock(&lock_access_log);

	if ((fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600)) < 0) {
		perror(log_path);
		pthread_mutex_unlock(&lock_access_log);
		return 1;
	}
	if (write(fd, str, strlen(str)) != strlen(str)) {
		perror(log_path);
		pthread_mutex_unlock(&lock_access_log);
		return 1;
	}
        write(fd, "\n", 1);
        fsync(fd);	
	
        close(fd);
	
	char mode[] = "0777";
	int int_filemod = strtol(mode, 0, 8);

	chmod(log_path, int_filemod);
	
	pthread_mutex_unlock(&lock_access_log);
	
        return 0;
}

void get_filepath_by_req(char* res_file, struct http_req* req)
{
	// определяем на основе запроса, что за файл открыть
	char const *index_file = "index.html";
	
	if (strcmp(req->uri_path, "/")==0)
	{
		strcat(res_file, index_file);
	}
	else
	{
		if(strlen(req->uri_path) > 0)
		{
			char* uri_path_minus_one = &((req->uri_path)[1]); //we skip first symbol '/' e.g. "/page1.html"
			strcat(res_file, uri_path_minus_one); 
		}
	}
}

void write_http_ok()
{
	char* http_result = "HTTP/1.1 200 OK\r\n";
	write(1,http_result,strlen(http_result));
	
	char* http_contype = "Content-Type: text/html\r\n";
	write(1,http_contype,strlen(http_contype));
	
	char* header_end = "\r\n";
	write(1,header_end,strlen(header_end));
}

void write_http_nosuchfile()
{
	char* http_result = "HTTP/1.1 404 Not Found\r\n";
	write(1,http_result,strlen(http_result));
	
	char* header_end = "\r\n";
	write(1,header_end,strlen(header_end));
}

int make_resp(struct http_req* req) 
{
        int fdin;
        struct stat statbuf;
        void* mmf_ptr;
	
	unsigned long pid = (unsigned long)getpid();
	
	
	char res_file[FILE_NAME_LEN] = "";
	if (getBasePath() != NULL && strlen(getBasePath()) > 0) {
		strncpy(res_file,getBasePath(),strlen(getBasePath()));
	}
	
	get_filepath_by_req(res_file, req);
	
	log_fstr(getLogPath(), " \n(pid=%lu) res_file=%s\n ", pid, res_file);
	
	// открываем
        if ((fdin=open(res_file, O_RDONLY)) < 0) {
                perror(res_file);
                return 1;
        }
	// размер
        if (fstat(fdin, &statbuf) < 0) {
                perror(res_file);
                return 1;
        }
	// mmf
        if ((mmf_ptr = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fdin, 0)) == MAP_FAILED) {
                perror("myfile");
                return 1;
        }
	
	write_http_ok();
	
	// Выводим запрошенный ресурс
        if (write(1,mmf_ptr,statbuf.st_size) != statbuf.st_size) {
                perror("stdout");
                return 1;
        }
	// Подчищаем ресурсы
        close(fdin);
        munmap(mmf_ptr,statbuf.st_size);
	return 0;
}

void prepare_paths(int argc, char* argv[])
{
	getBasePath()[0]='\0';
	getLogPath()[0]='\0';

	char const* log_file = "access.log";
	if ( argc > 2 ) { // задан каталог журнализации
		strncpy(getBasePath(), argv[1], strlen(argv[1]));
		strncpy(getLogPath(), argv[2], strlen(argv[2]));
		
		strcat(getLogPath(),"/");	
		strcat(getBasePath(),"/");
	}
	else
	{
		//strcat(log_path, "./log/");
	}
	
	strcat(getLogPath(),log_file);
}

int can_read()
{
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(STDIN_FILENO, &readfds);
	fd_set savefds = readfds;

	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	int chr;

	int sel_rv = select(1, &readfds, NULL, NULL, &timeout);
	
	if (sel_rv == -1) {
		return 0;
	}
	
	return 1;
}

struct resp_thread_params
{
	struct http_req* req;
};

void thread_cleanup_handler(void *arg)
{
	pthread_t thread_id = pthread_self();
	
	pthread_mutex_lock(&lock);
		remove_thread_from_list__unsafe(thread_id);
		fastFinishedThread = thread_id;
	pthread_mutex_unlock(&lock);
}

void* make_resp_thread_func(void* arg)
{
	struct resp_thread_params* params = (struct resp_thread_params*)arg;
	
	pthread_cleanup_push(thread_cleanup_handler, NULL);
	
	struct http_req req_local;
	memcpy(&req_local, params->req, sizeof(struct http_req));

	{ //registering the thread. we cant continue without proper thread registration
		pthread_mutex_lock(&lock);
		int add_res = add_thread_to_list__unsafe(pthread_self());
		pthread_mutex_unlock(&lock);
	
		while(add_res != 1) //we fill all MAX_THREADS lets wait for finish for someone
		{
			log_fstr(getLogPath(), "\ntoo many threads. waiting\n");
			pthread_mutex_lock(&lock);
			add_res = add_thread_to_list__unsafe(pthread_self());
			pthread_mutex_unlock(&lock);
		}
	}

	int resp_flag = make_resp(&req_local);
		
	if (resp_flag == 0)
	{
		//write_http_nosuchfile();
	}
	
	
	
	//sleep(30); //for debug reasons. if we handle req a long time
	
	
	
	pthread_cleanup_pop(1);
	
	thread_cleanup_handler(NULL);
	
	return NULL;
}

void do_resp_async(struct http_req* req)
{
	struct resp_thread_params thread_params;
	thread_params.req = req;
	pthread_t thread_id;
	
	{
		pthread_mutex_lock(&lock);
			fastFinishedThread = 0;
		pthread_mutex_unlock(&lock);
	}
	
	pthread_create(&thread_id, NULL, &make_resp_thread_func, &thread_params); 
	
	while(1) //waiting for thread is proper registered
	{
		//write(1,"111",3);
		pthread_mutex_lock(&lock);
			int thread_index = get_thread_id_index__unsafe(thread_id);
			pthread_t fashFinishedCopy = fastFinishedThread;	
		pthread_mutex_unlock(&lock);
		
		if(thread_index != -1)
			break;
			
		if(fashFinishedCopy == thread_id)
			break; //in case of when a new thread is finished before this while(1) cycle
	}
	
	{
		pthread_mutex_lock(&lock);
			fastFinishedThread = 0;
		pthread_mutex_unlock(&lock);
	}
	
	//and resume it only here somehow
		
	pthread_detach(thread_id);
	//pthread_join(thread_id, NULL);
	
	//int resp_flag = make_resp(req);	
	//if (resp_flag == 0)
	//{
		//write_http_nosuchfile();
	//}
}

int main (int argc, char* argv[]) 
{
	//getBasePath() //каталог с контентом
	//getLogPath() - каталог для ведения журнала

	memset(&threads, 0, sizeof(pthread_t)*MAX_THREADS);
	
	if (pthread_mutex_init(&lock, NULL) != 0) 
	{
		const char* str = "mutex init has failed";
		write(2,str,strlen(str));
		return 1;
	}
	
	if (pthread_mutex_init(&lock_access_log, NULL) != 0) 
	{
		const char* str = "mutex init has failed";
		write(2,str,strlen(str));
		return 1;
	}

	prepare_paths(argc, argv);
	
	unsigned long pid = (unsigned long)getpid();
	
	log_fstr(getLogPath(), " \nSTARTING (pid=%lu)\n ", pid);
	
	log_fstr(getLogPath(), " log_path=%s ", getLogPath());	//expected: /usr/local/bin/myweb_folder/log/access.log 
	log_fstr(getLogPath(), " base_path=%s ", getBasePath());	//expected: /usr/local/bin/myweb_folder/webroot/ 
	
	while(1)
	{
		if(can_read() == 1)
		{
			log_fstr(getLogPath(), "\n---the request itself (pid=%lu):-----------\n", pid);
	
			char buf[HTTP_HEADER_LEN];
			memset(buf, 0, sizeof(buf));
	
			struct http_req req;
			memset(&req, 0, sizeof(struct http_req));
			
			int line_num = 0;
			while(fgets(buf, sizeof(buf), stdin)) 
			{
				log_fstr(getLogPath(), "\n444\n", 0);
			
				line_num++;
			
				log_fstr(getLogPath(), "(pid=%lu) line%i: %s", pid, line_num, buf);

				int ret = fill_req(buf, &req);
				if (ret == 0) 
					// строка запроса обработана, переходим к следующей
					continue;
				if (ret == REQ_END ) 
					// конец HTTP запроса, вываливаемся на обработку
					break;
				else
					// какая-то ошибка 
					printf("Error: %d\n", ret);
			}
			
			log_fstr(getLogPath(), "\n---end of the request itself (pid=%lu):----\n", pid);
	
			log_fstr(getLogPath(), "\nParsed request (pid=%lu): request=%s, method=%s, uri=%s, uri_path=%s\n", pid, req.request, req.method, req.uri, req.uri_path);
		
			if(strstr(req.uri_path, "exit") != NULL)
				break; //exit code for server
	
			do_resp_async(&req);
		}
	}
	
	while(1)
	{
		pthread_mutex_lock(&lock);
		if(is_any_thread_in_list__unsafe() == 0)
			break;
		else
			log_fstr(getLogPath(), "\nwaiting for threads\n", pid);
			sleep(1);
		pthread_mutex_unlock(&lock);
	}
	
	pthread_mutex_destroy(&lock);
	pthread_mutex_destroy(&lock_access_log);
	
	log_fstr(getLogPath(), " \nFINISH (pid=%lu)\n ", pid);
}
