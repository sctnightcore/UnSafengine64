// ----------------------------------------------------------------------
// Resolve forwarded func.
//
//  ucrt --> ms-win-crt- * 
//  ntdll --> kernel32
// ----------------------------------------------------------------------


#include "pin.H"
#include <iostream>

struct CRT_DLL_NAME_FUNC {
	const char* dll_name;
	const char** funcs;
};

struct KERNEL32_TO_NTDLL {
	const char* ker_name;
	const char* nt_name;
};

#define NULL 0


const char* conio_funcs[] = {
"__conio_common_vcprintf", "__conio_common_vcprintf_p", "__conio_common_vcprintf_s", "__conio_common_vcscanf", "__conio_common_vcwprintf", "__conio_common_vcwprintf_p", "__conio_common_vcwprintf_s", "__conio_common_vcwscanf",
"_cgets", "_cgets_s", "_cgetws", "_cgetws_s", "_cputs", "_cputws", "_getch", "_getch_nolock",
"_getche", "_getche_nolock", "_getwch", "_getwch_nolock", "_getwche", "_getwche_nolock", "_putch", "_putch_nolock",
"_putwch", "_putwch_nolock", "_ungetch", "_ungetch_nolock", "_ungetwch", "_ungetwch_nolock", NULL };

const char* convert_funcs[] = {
"__toascii", "_atodbl", "_atodbl_l", "_atof_l", "_atoflt", "_atoflt_l", "_atoi64", "_atoi64_l",
"_atoi_l", "_atol_l", "_atoldbl", "_atoldbl_l", "_atoll_l", "_ecvt", "_ecvt_s", "_fcvt",
"_fcvt_s", "_gcvt", "_gcvt_s", "_i64toa", "_i64toa_s", "_i64tow", "_i64tow_s", "_itoa",
"_itoa_s", "_itow", "_itow_s", "_ltoa", "_ltoa_s", "_ltow", "_ltow_s", "_strtod_l",
"_strtof_l", "_strtoi64", "_strtoi64_l", "_strtoimax_l", "_strtol_l", "_strtold_l", "_strtoll_l", "_strtoui64",
"_strtoui64_l", "_strtoul_l", "_strtoull_l", "_strtoumax_l", "_ui64toa", "_ui64toa_s", "_ui64tow", "_ui64tow_s",
"_ultoa", "_ultoa_s", "_ultow", "_ultow_s", "_wcstod_l", "_wcstof_l", "_wcstoi64", "_wcstoi64_l",
"_wcstoimax_l", "_wcstol_l", "_wcstold_l", "_wcstoll_l", "_wcstombs_l", "_wcstombs_s_l", "_wcstoui64", "_wcstoui64_l",
"_wcstoul_l", "_wcstoull_l", "_wcstoumax_l", "_wctomb_l", "_wctomb_s_l", "_wtof", "_wtof_l", "_wtoi",
"_wtoi64", "_wtoi64_l", "_wtoi_l", "_wtol", "_wtol_l", "_wtoll", "_wtoll_l", "atof",
"atoi", "atol", "atoll", "btowc", "c16rtomb", "c32rtomb", "mbrtoc16", "mbrtoc32",
"mbrtowc", "mbsrtowcs", "mbsrtowcs_s", "mbstowcs", "mbstowcs_s", "mbtowc", "strtod", "strtof",
"strtoimax", "strtol", "strtold", "strtoll", "strtoul", "strtoull", "strtoumax", "wcrtomb",
"wcrtomb_s", "wcsrtombs", "wcsrtombs_s", "wcstod", "wcstof", "wcstoimax", "wcstol", "wcstold",
"wcstoll", "wcstombs", "wcstombs_s", "wcstoul", "wcstoull", "wcstoumax", "wctob", "wctomb",
"wctomb_s", "wctrans", NULL };

const char* environment_funcs[] = {
"__p__environ", "__p__wenviron", "_dupenv_s", "_putenv", "_putenv_s", "_searchenv", "_searchenv_s", "_wdupenv_s",
"_wgetcwd", "_wgetdcwd", "_wgetenv", "_wgetenv_s", "_wputenv", "_wputenv_s", "_wsearchenv", "_wsearchenv_s",
"getenv", "getenv_s", NULL };

const char* filesytem_funcs[] = {
"_access", "_access_s", "_chdir", "_chdrive", "_chmod", "_findclose", "_findfirst32", "_findfirst32i64",
"_findfirst64", "_findfirst64i32", "_findnext32", "_findnext32i64", "_findnext64", "_findnext64i32", "_fstat32", "_fstat32i64",
"_fstat64", "_fstat64i32", "_fullpath", "_getdiskfree", "_getdrive", "_getdrives", "_lock_file", "_makepath",
"_makepath_s", "_mkdir", "_rmdir", "_splitpath", "_splitpath_s", "_stat32", "_stat32i64", "_stat64",
"_stat64i32", "_umask", "_umask_s", "_unlink", "_unlock_file", "_waccess", "_waccess_s", "_wchdir",
"_wchmod", "_wfindfirst32", "_wfindfirst32i64", "_wfindfirst64", "_wfindfirst64i32", "_wfindnext32", "_wfindnext32i64", "_wfindnext64",
"_wfindnext64i32", "_wfullpath", "_wmakepath", "_wmakepath_s", "_wmkdir", "_wremove", "_wrename", "_wrmdir",
"_wsplitpath", "_wsplitpath_s", "_wstat32", "_wstat32i64", "_wstat64", "_wstat64i32", "_wunlink", "remove",
"rename", NULL };

const char* heap_funcs[] = {
"_aligned_free", "_aligned_malloc", "_aligned_msize", "_aligned_offset_malloc", "_aligned_offset_realloc", "_aligned_offset_recalloc", "_aligned_realloc", "_aligned_recalloc",
"_callnewh", "_calloc_base", "_expand", "_free_base", "_get_heap_handle", "_heapchk", "_heapmin", "_heapwalk",
"_malloc_base", "_msize", "_query_new_handler", "_query_new_mode", "_realloc_base", "_recalloc", "_set_new_mode", "calloc",
"free", "malloc", "realloc", NULL };

const char* locale_funcs[] = {
"___lc_codepage_func", "___lc_collate_cp_func", "___lc_locale_name_func", "___mb_cur_max_func", "___mb_cur_max_l_func", "__initialize_lconv_for_unsigned_char", "__pctype_func", "__pwctype_func",
"_configthreadlocale", "_create_locale", "_free_locale", "_get_current_locale", "_getmbcp", "_lock_locales", "_setmbcp", "_unlock_locales",
"_wcreate_locale", "_wsetlocale", "localeconv", "setlocale", NULL };

const char* math_funcs[] = {
"_Cbuild", "_Cmulcc", "_Cmulcr", "_FCbuild", "_FCmulcc", "_FCmulcr", "_LCbuild", "_LCmulcc",
"_LCmulcr", "__setusermatherr", "_cabs", "_chgsign", "_chgsignf", "_copysign", "_copysignf", "_d_int",
"_dclass", "_dexp", "_dlog", "_dnorm", "_dpcomp", "_dpoly", "_dscale", "_dsign",
"_dsin", "_dtest", "_dunscale", "_except1", "_fd_int", "_fdclass", "_fdexp", "_fdlog",
"_fdnorm", "_fdopen", "_fdpcomp", "_fdpoly", "_fdscale", "_fdsign", "_fdsin", "_fdtest",
"_fdunscale", "_finite", "_finitef", "_fpclass", "_fpclassf", "_get_FMA3_enable", "_hypot", "_hypotf",
"_isnan", "_isnanf", "_j0", "_j1", "_jn", "_ld_int", "_ldclass", "_ldexp",
"_ldlog", "_ldpcomp", "_ldpoly", "_ldscale", "_ldsign", "_ldsin", "_ldtest", "_ldunscale",
"_logb", "_logbf", "_nextafter", "_nextafterf", "_scalb", "_scalbf", "_set_FMA3_enable", "_y0",
"_y1", "_yn", "acos", "acosf", "acosh", "acoshf", "acoshl", "asin",
"asinf", "asinh", "asinhf", "asinhl", "atan", "atan2", "atan2f", "atanf",
"atanh", "atanhf", "atanhl", "cabs", "cabsf", "cabsl", "cacos", "cacosf",
"cacosh", "cacoshf", "cacoshl", "cacosl", "carg", "cargf", "cargl", "casin",
"casinf", "casinh", "casinhf", "casinhl", "casinl", "catan", "catanf", "catanh",
"catanhf", "catanhl", "catanl", "cbrt", "cbrtf", "cbrtl", "ccos", "ccosf",
"ccosh", "ccoshf", "ccoshl", "ccosl", "ceil", "ceilf", "cexp", "cexpf",
"cexpl", "cimag", "cimagf", "cimagl", "clog", "clog10", "clog10f", "clog10l",
"clogf", "clogl", "conj", "conjf", "conjl", "copysign", "copysignf", "copysignl",
"cos", "cosf", "cosh", "coshf", "cpow", "cpowf", "cpowl", "cproj",
"cprojf", "cprojl", "creal", "crealf", "creall", "csin", "csinf", "csinh",
"csinhf", "csinhl", "csinl", "csqrt", "csqrtf", "csqrtl", "ctan", "ctanf",
"ctanh", "ctanhf", "ctanhl", "ctanl", "erf", "erfc", "erfcf", "erfcl",
"erff", "erfl", "exp", "exp2", "exp2f", "exp2l", "expf", "expm1",
"expm1f", "expm1l", "fabs", "fdim", "fdimf", "fdiml", "floor", "floorf",
"fma", "fmaf", "fmal", "fmax", "fmaxf", "fmaxl", "fmin", "fminf",
"fminl", "fmod", "fmodf", "frexp", "hypot", "ilogb", "ilogbf", "ilogbl",
"ldexp", "lgamma", "lgammaf", "lgammal", "llrint", "llrintf", "llrintl", "llround",
"llroundf", "llroundl", "log", "log10", "log10f", "log1p", "log1pf", "log1pl",
"log2", "log2f", "log2l", "logb", "logbf", "logbl", "logf", "lrint",
"lrintf", "lrintl", "lround", "lroundf", "lroundl", "modf", "modff", "nan",
"nanf", "nanl", "nearbyint", "nearbyintf", "nearbyintl", "nextafter", "nextafterf", "nextafterl",
"nexttoward", "nexttowardf", "nexttowardl", "norm", "normf", "norml", "pow", "powf",
"remainder", "remainderf", "remainderl", "remquo", "remquof", "remquol", "rint", "rintf",
"rintl", "round", "roundf", "roundl", "scalbln", "scalblnf", "scalblnl", "scalbn",
"scalbnf", "scalbnl", "sin", "sinf", "sinh", "sinhf", "sqrt", "sqrtf",
"tan", "tanf", "tanh", "tanhf", "tgamma", "tgammaf", "tgammal", "trunc",
"truncf", "truncl", NULL };

const char* multbyte_funcs[] = {
"__p__mbcasemap", "__p__mbctype", "_ismbbalnum", "_ismbbalnum_l", "_ismbbalpha", "_ismbbalpha_l", "_ismbbblank", "_ismbbblank_l",
"_ismbbgraph", "_ismbbgraph_l", "_ismbbkalnum", "_ismbbkalnum_l", "_ismbbkana", "_ismbbkana_l", "_ismbbkprint", "_ismbbkprint_l",
"_ismbbkpunct", "_ismbbkpunct_l", "_ismbblead", "_ismbblead_l", "_ismbbprint", "_ismbbprint_l", "_ismbbpunct", "_ismbbpunct_l",
"_ismbbtrail", "_ismbbtrail_l", "_ismbcalnum", "_ismbcalnum_l", "_ismbcalpha", "_ismbcalpha_l", "_ismbcblank", "_ismbcblank_l",
"_ismbcdigit", "_ismbcdigit_l", "_ismbcgraph", "_ismbcgraph_l", "_ismbchira", "_ismbchira_l", "_ismbckata", "_ismbckata_l",
"_ismbcl0", "_ismbcl0_l", "_ismbcl1", "_ismbcl1_l", "_ismbcl2", "_ismbcl2_l", "_ismbclegal", "_ismbclegal_l",
"_ismbclower", "_ismbclower_l", "_ismbcprint", "_ismbcprint_l", "_ismbcpunct", "_ismbcpunct_l", "_ismbcspace", "_ismbcspace_l",
"_ismbcsymbol", "_ismbcsymbol_l", "_ismbcupper", "_ismbcupper_l", "_ismbslead", "_ismbslead_l", "_ismbstrail", "_ismbstrail_l",
"_mbbtombc", "_mbbtombc_l", "_mbbtype", "_mbbtype_l", "_mbcasemap", "_mbccpy", "_mbccpy_l", "_mbccpy_s",
"_mbccpy_s_l", "_mbcjistojms", "_mbcjistojms_l", "_mbcjmstojis", "_mbcjmstojis_l", "_mbclen", "_mbclen_l", "_mbctohira",
"_mbctohira_l", "_mbctokata", "_mbctokata_l", "_mbctolower", "_mbctolower_l", "_mbctombb", "_mbctombb_l", "_mbctoupper",
"_mbctoupper_l", "_mblen_l", "_mbsbtype", "_mbsbtype_l", "_mbscat_s", "_mbscat_s_l", "_mbschr", "_mbschr_l",
"_mbscmp", "_mbscmp_l", "_mbscoll", "_mbscoll_l", "_mbscpy_s", "_mbscpy_s_l", "_mbscspn", "_mbscspn_l",
"_mbsdec", "_mbsdec_l", "_mbsdup", "_mbsicmp", "_mbsicmp_l", "_mbsicoll", "_mbsicoll_l", "_mbsinc",
"_mbsinc_l", "_mbslen", "_mbslen_l", "_mbslwr", "_mbslwr_l", "_mbslwr_s", "_mbslwr_s_l", "_mbsnbcat",
"_mbsnbcat_l", "_mbsnbcat_s", "_mbsnbcat_s_l", "_mbsnbcmp", "_mbsnbcmp_l", "_mbsnbcnt", "_mbsnbcnt_l", "_mbsnbcoll",
"_mbsnbcoll_l", "_mbsnbcpy", "_mbsnbcpy_l", "_mbsnbcpy_s", "_mbsnbcpy_s_l", "_mbsnbicmp", "_mbsnbicmp_l", "_mbsnbicoll",
"_mbsnbicoll_l", "_mbsnbset", "_mbsnbset_l", "_mbsnbset_s", "_mbsnbset_s_l", "_mbsncat", "_mbsncat_l", "_mbsncat_s",
"_mbsncat_s_l", "_mbsnccnt", "_mbsnccnt_l", "_mbsncmp", "_mbsncmp_l", "_mbsncoll", "_mbsncoll_l", "_mbsncpy",
"_mbsncpy_l", "_mbsncpy_s", "_mbsncpy_s_l", "_mbsnextc", "_mbsnextc_l", "_mbsnicmp", "_mbsnicmp_l", "_mbsnicoll",
"_mbsnicoll_l", "_mbsninc", "_mbsninc_l", "_mbsnlen", "_mbsnlen_l", "_mbsnset", "_mbsnset_l", "_mbsnset_s",
"_mbsnset_s_l", "_mbspbrk", "_mbspbrk_l", "_mbsrchr", "_mbsrchr_l", "_mbsrev", "_mbsrev_l", "_mbsset",
"_mbsset_l", "_mbsset_s", "_mbsset_s_l", "_mbsspn", "_mbsspn_l", "_mbsspnp", "_mbsspnp_l", "_mbsstr",
"_mbsstr_l", "_mbstok", "_mbstok_l", "_mbstok_s", "_mbstok_s_l", "_mbstowcs_l", "_mbstowcs_s_l", "_mbstrlen",
"_mbstrlen_l", "_mbstrnlen", "_mbstrnlen_l", "_mbsupr", "_mbsupr_l", "_mbsupr_s", "_mbsupr_s_l", "_mbtowc_l",
NULL };



const char* process_funcs[] = {
"_beep", "_cwait", "_execl", "_execle", "_execlp", "_execlpe", "_execv", "_execve",
"_execvp", "_execvpe", "_loaddll", "_spawnl", "_spawnle", "_spawnlp", "_spawnlpe", "_spawnv",
"_spawnve", "_spawnvp", "_spawnvpe", "_unloaddll", "_wexecl", "_wexecle", "_wexeclp", "_wexeclpe",
"_wexecv", "_wexecve", "_wexecvp", "_wexecvpe", "_wspawnl", "_wspawnle", "_wspawnlp", "_wspawnlpe",
"_wspawnv", "_wspawnve", "_wspawnvp", "_wspawnvpe", NULL };

const char* runtime_funcs[] = {
"_Exit", "__doserrno", "__fpe_flt_rounds", "__fpecode", "__p___argc", "__p___argv", "__p___wargv", "__p__acmdln",
"__p__pgmptr", "__p__wcmdln", "__p__wpgmptr", "__pxcptinfoptrs", "__sys_errlist", "__sys_nerr", "__threadhandle", "__threadid",
"__wcserror", "__wcserror_s", "_assert", "_beginthread", "_beginthreadex", "_c_exit", "_cexit", "_clearfp",
"_configure_narrow_argv", "_configure_wide_argv", "_control87", "_controlfp", "_controlfp_s", "_crt_at_quick_exit", "_crt_atexit", "_endthread",
"_endthreadex", "_errno", "_execute_onexit_table", "_exit", "_fpieee_flt", "_fpreset", "_get_doserrno", "_get_errno",
"_get_initial_narrow_environment", "_get_initial_wide_environment", "_get_invalid_parameter_handler", "_get_narrow_winmain_command_line", "_get_pgmptr", "_get_terminate", "_get_thread_local_invalid_parameter_handler", "_get_wide_winmain_command_line",
"_get_wpgmptr", "_getdllprocaddr", "_getpid", "_initialize_narrow_environment", "_initialize_onexit_table", "_initialize_wide_environment", "_initterm", "_initterm_e",
"_invalid_parameter_noinfo", "_invalid_parameter_noinfo_noreturn", "_invoke_watson", "_query_app_type", "_register_onexit_function", "_register_thread_local_exe_atexit_callback", "_resetstkoflw", "_seh_filter_dll",
"_seh_filter_exe", "_set_abort_behavior", "_set_app_type", "_set_controlfp", "_set_doserrno", "_set_errno", "_set_error_mode", "_set_invalid_parameter_handler",
"_set_new_handler", "_set_thread_local_invalid_parameter_handler", "_seterrormode", "_sleep", "_statusfp", "_strerror", "_strerror_s", "_wassert",
"_wcserror", "_wcserror_s", "_wperror", "_wsystem", "abort", "exit", "feclearexcept", "fegetenv",
"fegetexceptflag", "fegetround", "feholdexcept", "fesetenv", "fesetexceptflag", "fesetround", "fetestexcept", "perror",
"quick_exit", "raise", "set_terminate", "signal", "strerror", "strerror_s", "system", "terminate",
NULL };

const char* stdio_funcs[] = {
"__acrt_iob_func", "__p__commode", "__p__fmode", "__stdio_common_vfprintf", "__stdio_common_vfprintf_p", "__stdio_common_vfprintf_s", "__stdio_common_vfscanf", "__stdio_common_vfwprintf",
"__stdio_common_vfwprintf_p", "__stdio_common_vfwprintf_s", "__stdio_common_vfwscanf", "__stdio_common_vsnprintf_s", "__stdio_common_vsnwprintf_s", "__stdio_common_vsprintf", "__stdio_common_vsprintf_p", "__stdio_common_vsprintf_s",
"__stdio_common_vsscanf", "__stdio_common_vswprintf", "__stdio_common_vswprintf_p", "__stdio_common_vswprintf_s", "__stdio_common_vswscanf", "_chsize", "_chsize_s", "_close",
"_commit", "_creat", "_dup", "_dup2", "_eof", "_fclose_nolock", "_fcloseall", "_fflush_nolock",
"_fgetc_nolock", "_fgetchar", "_fgetwc_nolock", "_fgetwchar", "_filelength", "_filelengthi64", "_fileno", "_flushall",
"_fputc_nolock", "_fputchar", "_fputwc_nolock", "_fputwchar", "_fread_nolock", "_fread_nolock_s", "_fseek_nolock", "_fseeki64",
"_fseeki64_nolock", "_fsopen", "_ftell_nolock", "_ftelli64", "_ftelli64_nolock", "_fwrite_nolock", "_get_fmode", "_get_osfhandle",
"_get_printf_count_output", "_get_stream_buffer_pointers", "_getc_nolock", "_getcwd", "_getdcwd", "_getmaxstdio", "_getw", "_getwc_nolock",
"_getws", "_getws_s", "_isatty", "_kbhit", "_locking", "_lseek", "_lseeki64", "_mktemp",
"_mktemp_s", "_open", "_open_osfhandle", "_pclose", "_pipe", "_popen", "_putc_nolock", "_putw",
"_putwc_nolock", "_putws", "_read", "_rmtmp", "_set_fmode", "_set_printf_count_output", "_setmaxstdio", "_setmode",
"_sopen", "_sopen_dispatch", "_sopen_s", "_tell", "_telli64", "_tempnam", "_ungetc_nolock", "_ungetwc_nolock",
"_wcreat", "_wfdopen", "_wfopen", "_wfopen_s", "_wfreopen", "_wfreopen_s", "_wfsopen", "_wmktemp",
"_wmktemp_s", "_wopen", "_wpopen", "_write", "_wsopen", "_wsopen_dispatch", "_wsopen_s", "_wtempnam",
"_wtmpnam", "_wtmpnam_s", "clearerr", "clearerr_s", "fclose", "feof", "ferror", "fflush",
"fgetc", "fgetpos", "fgets", "fgetwc", "fgetws", "fopen", "fopen_s", "fputc",
"fputs", "fputwc", "fputws", "fread", "fread_s", "freopen", "freopen_s", "fseek",
"fsetpos", "ftell", "fwrite", "getc", "getchar", "gets", "gets_s", "getwc",
"getwchar", "putc", "putchar", "puts", "putwc", "putwchar", "rewind", "setbuf",
"setvbuf", "tmpfile", "tmpfile_s", "tmpnam", "tmpnam_s", "ungetc", "ungetwc", NULL };


const char* string_funcs[] = {
"__isascii", "__iscsym", "__iscsymf", "__iswcsym", "__iswcsymf", "__strncnt", "__wcsncnt", "_isalnum_l",
"_isalpha_l", "_isblank_l", "_iscntrl_l", "_isctype", "_isctype_l", "_isdigit_l", "_isgraph_l", "_isleadbyte_l",
"_islower_l", "_isprint_l", "_ispunct_l", "_isspace_l", "_isupper_l", "_iswalnum_l", "_iswalpha_l", "_iswblank_l",
"_iswcntrl_l", "_iswcsym_l", "_iswcsymf_l", "_iswctype_l", "_iswdigit_l", "_iswgraph_l", "_iswlower_l", "_iswprint_l",
"_iswpunct_l", "_iswspace_l", "_iswupper_l", "_iswxdigit_l", "_isxdigit_l", "_memccpy", "_memicmp", "_memicmp_l",
"_strcoll_l", "_strdup", "_stricmp", "_stricmp_l", "_stricoll", "_stricoll_l", "_strlwr", "_strlwr_l",
"_strlwr_s", "_strlwr_s_l", "_strncoll", "_strncoll_l", "_strnicmp", "_strnicmp_l", "_strnicoll", "_strnicoll_l",
"_strnset", "_strnset_s", "_strrev", "_strset", "_strset_s", "_strupr", "_strupr_l", "_strupr_s",
"_strupr_s_l", "_strxfrm_l", "_tolower", "_tolower_l", "_toupper", "_toupper_l", "_towlower_l", "_towupper_l",
"_wcscoll_l", "_wcsdup", "_wcsicmp", "_wcsicmp_l", "_wcsicoll", "_wcsicoll_l", "_wcslwr", "_wcslwr_l",
"_wcslwr_s", "_wcslwr_s_l", "_wcsncoll", "_wcsncoll_l", "_wcsnicmp", "_wcsnicmp_l", "_wcsnicoll", "_wcsnicoll_l",
"_wcsnset", "_wcsnset_s", "_wcsrev", "_wcsset", "_wcsset_s", "_wcsupr", "_wcsupr_l", "_wcsupr_s",
"_wcsupr_s_l", "_wcsxfrm_l", "_wctype", "is_wctype", "isalnum", "isalpha", "isblank", "iscntrl",
"isdigit", "isgraph", "isleadbyte", "islower", "isprint", "ispunct", "isspace", "isupper",
"iswalnum", "iswalpha", "iswascii", "iswblank", "iswcntrl", "iswctype", "iswdigit", "iswgraph",
"iswlower", "iswprint", "iswpunct", "iswspace", "iswupper", "iswxdigit", "isxdigit", "mblen",
"mbrlen", "memcpy_s", "memmove_s", "memset", "strcat", "strcat_s", "strcmp", "strcoll",
"strcpy", "strcpy_s", "strcspn", "strlen", "strncat", "strncat_s", "strncmp", "strncpy",
"strncpy_s", "strnlen", "strpbrk", "strspn", "strtok", "strtok_s", "strxfrm", "tolower",
"toupper", "towctrans", "towlower", "towupper", "wcscat", "wcscat_s", "wcscmp", "wcscoll",
"wcscpy", "wcscpy_s", "wcscspn", "wcslen", "wcsncat", "wcsncat_s", "wcsncmp", "wcsncpy",
"wcsncpy_s", "wcsnlen", "wcspbrk", "wcsspn", "wcstok", "wcstok_s", "wcsxfrm", "wctype",
"wmemcpy_s", "wmemmove_s", NULL };

const char* time_funcs[] = {
"_Getdays", "_Getmonths", "_Gettnames", "_Strftime", "_W_Getdays", "_W_Getmonths", "_W_Gettnames", "_Wcsftime",
"__daylight", "__dstbias", "__timezone", "__tzname", "_ctime32", "_ctime32_s", "_ctime64", "_ctime64_s",
"_difftime32", "_difftime64", "_ftime32", "_ftime32_s", "_ftime64", "_ftime64_s", "_futime32", "_futime64",
"_get_daylight", "_get_dstbias", "_get_timezone", "_get_tzname", "_getsystime", "_gmtime32", "_gmtime32_s", "_gmtime64",
"_gmtime64_s", "_localtime32", "_localtime32_s", "_localtime64", "_localtime64_s", "_mkgmtime32", "_mkgmtime64", "_mktime32",
"_mktime64", "_setsystime", "_strdate", "_strdate_s", "_strftime_l", "_strtime", "_strtime_s", "_time32",
"_time64", "_timespec32_get", "_timespec64_get", "_tzset", "_utime32", "_utime64", "_wasctime", "_wasctime_s",
"_wcsftime_l", "_wctime32", "_wctime32_s", "_wctime64", "_wctime64_s", "_wstrdate", "_wstrdate_s", "_wstrtime",
"_wstrtime_s", "_wutime32", "_wutime64", "asctime", "asctime_s", "clock", "strftime", "wcsftime",
NULL };


const char* utility_funcs[] = {
"_abs64", "_byteswap_uint64", "_byteswap_ulong", "_byteswap_ushort", "_lfind", "_lfind_s", "_lrotl", "_lrotr",
"_lsearch", "_lsearch_s", "_rotl", "_rotl64", "_rotr", "_rotr64", "_swab", "abs",
"bsearch", "bsearch_s", "div", "imaxabs", "imaxdiv", "labs", "ldiv", "llabs",
"lldiv", "qsort", "qsort_s", "rand", "rand_s", "srand", NULL };


const CRT_DLL_NAME_FUNC all_crt_dll_name_func[] = {

	{ "api-ms-win-crt-conio-l1-1-0.dll", conio_funcs },
	{ "api-ms-win-crt-convert-l1-1-0.dll", convert_funcs },
	{ "api-ms-win-crt-environment-l1-1-0.dll", environment_funcs },
	{ "api-ms-win-crt-filesystem-l1-1-0.dll", filesytem_funcs },
	{"api-ms-win-crt-heap-l1-1-0.dll", heap_funcs },
	{"api-ms-win-crt-locale-l1-1-0.dll", locale_funcs},
	{"api-ms-win-crt-math-l1-1-0.dll", math_funcs},
	{"api-ms-win-crt-multibyte-l1-1-0.dll", multbyte_funcs},
	{"api-ms-win-crt-process-l1-1-0.dll", process_funcs},
	{"api-ms-win-crt-runtime-l1-1-0.dll", runtime_funcs},
	{"api-ms-win-crt-stdio-l1-1-0.dll", stdio_funcs},
	{"api-ms-win-crt-string-l1-1-0.dll", string_funcs},
	{"api-ms-win-crt-time-l1-1-0.dll", time_funcs},
	{"api-ms-win-crt-utility-l1-1-0.dll", utility_funcs},
	{0, 0}
};


const char* get_crt_dll_name(const char* ucrt_fname)
{

	int i = 0;
	while (all_crt_dll_name_func[i].dll_name) {
		int j = 0;
		const char** funcs = all_crt_dll_name_func[i].funcs;
		while (funcs[j]) {

			if (strcmp(funcs[j], ucrt_fname) == 0) {
				return all_crt_dll_name_func[i].dll_name;
			}
			j++;
		}
		i++;
	}
	return NULL;

}

const KERNEL32_TO_NTDLL all_kernel32_ntdll_name[] = {

	{ "AcquireSRWLockExclusive", "RtlAcquireSRWLockExclusive" },
	{ "AcquireSRWLockShared", "RtlAcquireSRWLockShared" },
	{ "AddVectoredContinueHandler", "RtlAddVectoredContinueHandler" },
	{ "AddVectoredExceptionHandler", "RtlAddVectoredExceptionHandler" },
	{ "CancelThreadpoolIo", "TpCancelAsyncIoOperation" },
	{ "CloseThreadpool", "TpReleasePool" },
	{ "CloseThreadpoolCleanupGroup", "TpReleaseCleanupGroup" },
	{ "CloseThreadpoolCleanupGroupMembers", "TpReleaseCleanupGroupMembers" },
	{ "CloseThreadpoolIo", "TpReleaseIoCompletion" },
	{ "CloseThreadpoolTimer", "TpReleaseTimer" },
	{ "CloseThreadpoolWait", "TpReleaseWait" },
	{ "CloseThreadpoolWork", "TpReleaseWork" },
	{ "DecodePointer", "RtlDecodePointer" },
	{ "DecodeSystemPointer", "RtlDecodeSystemPointer" },
	{ "DeleteCriticalSection", "RtlDeleteCriticalSection" },
	{ "DisassociateCurrentThreadFromCallback", "TpDisassociateCallback" },
	{ "EncodePointer", "RtlEncodePointer" },
	{ "EncodeSystemPointer", "RtlEncodeSystemPointer" },
	{ "EnterCriticalSection", "RtlEnterCriticalSection" },
	{ "ExitThread", "RtlExitUserThread" },
	{ "FlushProcessWriteBuffers", "NtFlushProcessWriteBuffers" },
	{ "FreeLibraryWhenCallbackReturns", "TpCallbackUnloadDllOnCompletion" },
	{ "GetCurrentProcessorNumber", "RtlGetCurrentProcessorNumber" },
	{ "GetCurrentProcessorNumberEx", "RtlGetCurrentProcessorNumberEx" },
	{ "HeapAlloc", "RtlAllocateHeap" },
	{ "HeapReAlloc", "RtlReAllocateHeap" },
	{ "HeapSize", "RtlSizeHeap" },
	{ "InitOnceInitialize", "RtlRunOnceInitialize" },
	{ "InitializeConditionVariable", "RtlInitializeConditionVariable" },
	{ "InitializeCriticalSection", "RtlInitializeCriticalSection" },
	{ "InitializeSListHead", "RtlInitializeSListHead" },
	{ "InitializeSRWLock", "RtlInitializeSRWLock" },
	{ "InterlockedFlushSList", "RtlInterlockedFlushSList" },
	{ "InterlockedPopEntrySList", "RtlInterlockedPopEntrySList" },
	{ "InterlockedPushEntrySList", "RtlInterlockedPushEntrySList" },
	{ "InterlockedPushListSList", "RtlInterlockedPushListSList" },
	{ "InterlockedPushListSListEx", "RtlInterlockedPushListSListEx" },
	{ "IsThreadpoolTimerSet", "TpIsTimerSet" },
	{ "LeaveCriticalSection", "RtlLeaveCriticalSection" },
	{ "LeaveCriticalSectionWhenCallbackReturns", "TpCallbackLeaveCriticalSectionOnCompletion" },
	{ "QueryDepthSList", "RtlQueryDepthSList" },
	{ "ReleaseMutexWhenCallbackReturns", "TpCallbackReleaseMutexOnCompletion" },
	{ "ReleaseSRWLockExclusive", "RtlReleaseSRWLockExclusive" },
	{ "ReleaseSRWLockShared", "RtlReleaseSRWLockShared" },
	{ "ReleaseSemaphoreWhenCallbackReturns", "TpCallbackReleaseSemaphoreOnCompletion" },
	{ "RemoveVectoredContinueHandler", "RtlRemoveVectoredContinueHandler" },
	{ "RemoveVectoredExceptionHandler", "RtlRemoveVectoredExceptionHandler" },
	{ "ResolveDelayLoadedAPI", "LdrResolveDelayLoadedAPI" },
	{ "ResolveDelayLoadsFromDll", "LdrResolveDelayLoadsFromDll" },
	{ "RestoreLastError", "RtlRestoreLastWin32Error" },
	{ "RtlZeroMemory", "RtlZeroMemory" },
	{ "SetCriticalSectionSpinCount", "RtlSetCriticalSectionSpinCount" },
	{ "SetEventWhenCallbackReturns", "TpCallbackSetEventOnCompletion" },
	{ "SetThreadpoolThreadMaximum", "TpSetPoolMaxThreads" },
	{ "SetThreadpoolTimer", "TpSetTimer" },
	{ "SetThreadpoolTimerEx", "TpSetTimerEx" },
	{ "SetThreadpoolWait", "TpSetWait" },
	{ "SetThreadpoolWaitEx", "TpSetWaitEx" },
	{ "StartThreadpoolIo", "TpStartAsyncIoOperation" },
	{ "SubmitThreadpoolWork", "TpPostWork" },
	{ "TryAcquireSRWLockExclusive", "RtlTryAcquireSRWLockExclusive" },
	{ "TryAcquireSRWLockShared", "RtlTryAcquireSRWLockShared" },
	{ "TryEnterCriticalSection", "RtlTryEnterCriticalSection" },
	{ "VerSetConditionMask", "VerSetConditionMask" },
	{ "WaitForThreadpoolIoCallbacks", "TpWaitForIoCompletion" },
	{ "WaitForThreadpoolTimerCallbacks", "TpWaitForTimer" },
	{ "WaitForThreadpoolWaitCallbacks", "TpWaitForWait" },
	{ "WaitForThreadpoolWorkCallbacks", "TpWaitForWork" },
	{ "WakeAllConditionVariable", "RtlWakeAllConditionVariable" },
	{ "WakeConditionVariable", "RtlWakeConditionVariable" },
	{ "__C_specific_handler", "__C_specific_handler" },
	{ "__chkstk", "__chkstk" },
	{ "__misaligned_access", "__misaligned_access" },
	{ "_local_unwind", "_local_unwind" },
	{ 0,0 }

};

const char* get_ntdll_to_kernel32_name(const char* ntdll_name)
{	
	int i = 0;
	while (all_kernel32_ntdll_name[i].ker_name) {
		if (strcmp(all_kernel32_ntdll_name[i].nt_name, ntdll_name) == 0) {
			return all_kernel32_ntdll_name[i].ker_name;
		}
		i++;
	}
	return NULL;

}