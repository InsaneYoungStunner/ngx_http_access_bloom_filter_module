#include <ngx_http.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <math.h>
//误判率
#define false_positive 0.001

//用来生成hash函数的seed，最多14个，因为在nips=2^31时，对应的最好hash函数是14个。
static ngx_int_t seeds[14] = {5,7,11,13,31,37,61,127,211,359,409,601,997,1061};

static ngx_int_t ngx_http_access_bloom_filter_hashfunc(ngx_int_t seed, ngx_int_t size,in_addr_t addr);

struct ngx_http_access_bf_ip_s
{
    in_addr_t    addr;
    in_addr_t    mask;
    ngx_uint_t   deny;
};

typedef struct ngx_http_access_bf_ip_s ngx_http_access_bf_ip_t;

struct ngx_http_access_bloom_filter_loc_conf_s
{
  //白名单用来对一些bloom filter中出现的误判进行补救
  ngx_array_t*   allow_list; //array of ngx_http_access_bf_ip_t
  //deny ip 数
  ngx_uint_t     nips;
  ngx_uint_t     length;
  ngx_uint_t     nhashfunc;
  ngx_uint32_t   hash_buckets[1];//sort array
};

typedef struct ngx_http_access_bloom_filter_loc_conf_s ngx_http_access_bloom_filter_loc_conf_t;

static ngx_int_t
    ngx_http_access_bloom_filter_handler(ngx_http_request_t *r);
static ngx_int_t
    ngx_http_access_bloom_filter_inet(ngx_http_request_t *r,
        ngx_http_access_bloom_filter_loc_conf_t *abflcf,
              in_addr_t addr);
static ngx_int_t
    ngx_http_access_bloom_filter_found_deny_ip(ngx_http_request_t *r,
        ngx_http_access_bloom_filter_loc_conf_t*);
static char*
    ngx_http_access_bloom_filter(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
static void*
    ngx_http_access_bloom_filter_create_loc_conf(ngx_conf_t *cf);
static char*
    ngx_http_access_bloom_filter_merge_loc_conf(ngx_conf_t *cf);
static ngx_int_t
    ngx_http_access_bloom_filter_init(ngx_conf_t *cf);
static ngx_int_t
    ngx_http_access_bloom_filter_set_bit(ngx_http_access_bloom_filter_loc_conf_t *abflcf,
        ngx_cidr_t cidr);


static ngx_command_t ngx_http_access_bloom_filter_commands[] = {
  { //拒绝访问ip数，将根据该值决定hash_bucket数
    ngx_string("deny_numbers_bf"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                     |NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_access_bloom_filter_loc_conf_t,nips),
    NULL
  },
  {
    ngx_string("allow_bf"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                      |NGX_CONF_TAKE1,
    ngx_http_access_bloom_filter,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("deny_bf"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                     |NGX_CONF_TAKE1,
    ngx_http_access_bloom_filter,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },

  ngx_null_command
};

static ngx_http_module_t ngx_http_access_bloom_filter_module_ctx = {
    NULL,
    ngx_http_access_bloom_filter_init,

    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_access_bloom_filter_create_loc_conf,
    ngx_http_access_bloom_filter_merge_loc_conf
};


ngx_module_t ngx_http_access_bloom_filter_module = {
  NGX_MODULE_V1,
  &ngx_http_access_bloom_filter_module_ctx,           /* module context */
  ngx_http_access_bloom_filter_commands,              /* module directives */
  NGX_HTTP_MODULE,                       /* module type */
  NULL,                                  /* init master */
  NULL,                                  /* init module */
  NULL,                                  /* init process */
  NULL,                                  /* init thread */
  NULL,                                  /* exit thread */
  NULL,                                  /* exit process */
  NULL,                                  /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t
    ngx_http_access_bloom_filter_hashfunc(ngx_int_t seed,
        ngx_int_t size,in_addr_t addr)
{
  ngx_int_t         result;
  ngx_uint32_t      aton;
  //in_addr_t在unix中为uint32_t
  aton = (ngx_uint32_t)addr;
  result = seed * aton;
  return (size - 1) & result; //保证hash位置<=size
}

static ngx_int_t
    ngx_http_access_bloom_filter_set_bit(ngx_http_access_bloom_filter_loc_conf_t *abflcf,
        ngx_cidr_t cidr)
{
    ngx_int_t      i, position, n, m;
    for(i = 0;i < abflcf->nhashfunc; i++){
        position = ngx_http_access_bloom_filter_hashfunc(seed[i], abflcf->length, cidr.u.in.addr);
        n = position / 32;
        m = position % 32;
        abflcf->hash_buckets[n] = abflcf->hash_buckets[n] | (1 << (31 - m));
    }
    return NGX_OK;
}

static void*
    ngx_http_access_bloom_filter_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_access_bloom_filter_loc_conf_t *abflcf;
  abflcf = ngx_pcalloc(cf->pool,sizeof(ngx_http_access_bloom_filter_loc_conf_t));
  if(abflcf == NULL){
    return NGX_CONF_ERROR;
  }
  abflcf->nips = NGX_CONF_UNSET;
  return abflcf;
}

static char*
    ngx_http_access_bloom_filter_merge_loc_conf(ngx_conf_t *cf,
        void *parent,void *child)
{
   ngx_http_access_bloom_filter_loc_conf_t *p_abflcf = parent;
   ngx_http_access_bloom_filter_loc_conf_t *c_abflcf = child;
   if(c_abflcf->allow_list == NULL){
     c_abflcf->allow_list = p_abflcf->allow_list;
   }
   if(c_abflcf->hash_buckets == NULL){
     c_abflcf->hash_buckets = p_abflcf->hash_buckets;
     c_abflcf->length = p_abflcf->length;
     c_abflcf->nips = p_abflcf->nips;
     c_abflcf->nhashfunc = p_abflcf->nhashfunc;
   }
   return NGX_CONF_OK;
}

static ngx_int_t
    ngx_http_access_bloom_filter_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt         *h;
    ngx_http_core_main_conf_t   *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);\

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if(h == NULL)
      return NGX_ERROR;

    *h = ngx_http_access_bloom_filter_handler;
    return NGX_OK;
}

static ngx_int_t
    ngx_http_access_bloom_filter_handler(ngx_http_request_t *r)
{
    struct sockaddr_in                          *sin;
    ngx_http_access_bloom_filter_loc_conf_t     *abflcf;

    abflcf = ngx_http_get_module_loc_conf(r, ngx_http_access_bloom_filter_module);

    if(r->connection->sockaddr->sa_family == AF_INET){
      if(abflcf->allow_list || abflcf->hash_buckets){
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        return ngx_http_access_bloom_filter_inet(r, abflcf, sin->sin_addr.s_addr);
      }
    }
    //没有启用bloom filter，调用下一个
    return NGX_DECLINED;
}

static ngx_int_t
    ngx_http_access_bloom_filter_found_deny_ip(ngx_http_request_t *r,
        ngx_http_access_bloom_filter_loc_conf_t *abflcf)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_int_t      i, position, n, m;
    bool           result;

    result = true;

    for(i = 0; i < abflcf->nhashfunc; i++){
        position = ngx_http_access_bloom_filter_hashfunc(seed[i], abflcf->length, cidr.u.in.addr);
        n = position / 32;
        m = position % 32;
        result = result && (abflcf->hash_buckets[n] & (1 << (31 - m)));
    }
    //result为true代表ip在黑名单集合中
    if(result){
        //判断配置项中是satisfy all还是any
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "access forbidden by bloom filter");
        }

        return NGX_HTTP_FORBIDDEN;
    }

    //不在黑名单也不在白名单中，调用NGX_HTTP_ACCESS_PHASE阶段下一个handler或者调用下一阶段的第一个handler
    return NGX_DECLINED;


}

static ngx_int_t
    ngx_http_access_bloom_filter_inet(ngx_http_request_t *r,
        ngx_http_access_bloom_filter_loc_conf_t *abflcf, in_addr_t addr)
{
      ngx_uint_t         i;
      ngx_http_access_bf_ip_t *a_ip;
      if(abflcf->allow_list != NULL){
          a_ip = abflcf->allow_list->elts;
          for(i = 0;i < abflcf->allow_list->nelts; i++){

            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "access: %08XD %08XD %08XD",
                           addr, a_ip[i].mask, a_ip[i].addr);

            if ((addr & a_ip[i].mask) == a_ip[i].addr) {
                 return NGX_OK;
            }
          }
      }

      //不在白名单里
      if(abflcf->hash_buckets != NULL){
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "access: %08XD",addr);
        return ngx_http_access_bloom_filter_found_deny_ip(r,abflcf);
      }

      //没有明确deny或allow就按照顺序执行下一个ngx_http_handler_pt方法
      return NGX_DECLINED;
}

static char*
    ngx_http_access_bloom_filter(ngx_conf_t *cf,ngx_command_t *cmd,void *conf)
{
  ngx_http_access_bloom_filter_loc_conf_t *abflcf = conf;
  ngx_int_t                   rc;
  ngx_str_t                  *value;
  ngx_cidr_t                  cidr;
  ngx_http_access_bf_ip_t     *bfip;
  ngx_str_t                  *mark;
  ngx_int_t                   k;
  ngx_uint32_t                addr_for_mask;
  ngx_memzero(&cidr, sizeof(ngx_cidr_t));
  value = &cf->args->elts[1];
  mark = cf->args->elts;

  //处理ip4和ip6，如果无掩码则返回OK，有掩码且ip等于ip&掩码后的值则返回OK，否则为DONE
  rc = ngx_ptocidr(value, &cidr);

  if (rc == NGX_ERROR) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                  "invalid parameter \"%V\"", value);
      return NGX_CONF_ERROR;
  }

  if (rc == NGX_DONE) {
      ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                 "low address bits of %V are meaningless", value);
  }

#if (NGX_HAVE_INET6)

  if(cidr.family == AF_INET6){
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "ngx_http_access_bloom_filter_module is currently not supported for IPV6 \"%V\"", value);
      return NGX_CONF_ERROR;
  }

#endif

#if (NGX_HAVE_UNIX_DOMAIN)

  if(cidr.family == AF_UNIX){
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
              "ngx_http_access_bloom_filter_module is currently not supported for Local protocol \"%V\"", value);
      return NGX_CONF_ERROR;
  }

#endif

  if(cidr.family == AF_INET){
        //白名单放入数组
        if(mark[0].data[0] == 'a'){
              if(abflcf->allow_list == NULL){
                    abflcf->allow_list = ngx_array_create(cf->pool,
                                              4, sizeof(ngx_http_access_bf_ip_t));
                    if(abflcf->allow_list == NULL){
                      return NGX_CONF_ERROR;
                    }
              }

              bfip = ngx_array_push(alcf->allow_list);
              if(bfip == NULL){
                return NGX_CONF_ERROR;
              }

              bfip->mask = cidr.u.in.mask;
              bfip->addr = cidr.u.in.addr;
              bfip->deny = 0;
        }else{//deny ip
            if(abflcf->hash_buckets == NULL){
                if(abflcf->nips == NGX_CONF_UNSET)
                    return NGX_CONF_ERROR;
                abflcf->length = ceil(1.44 * abflcf->nips * (log(1 / false_positive) / log(2)));
                abflcf->hash_buckets = ngx_pcalloc(cf->pool,sizeof(ngx_uint32_t) * (abflcf->length / 32 + 1));
                if(abflcf->hash_buckets == NULL){
                  return NGX_CONF_ERROR;
                }
                k = ceil(0.693 * abflcf->length / abflcf->nips);
                abflcf->nhashfunc = k > 14 ? 14 : k;
              }
            /* 将ip hash进相应点*/
            for(addr_for_mask = (cidr.u.in.addr & cidr.u.in.mask);
                    addr_for_mask <= (cidr.u.in.addr | (~cidr.u.in.mask));
                        addr_for_mask++){
                ngx_http_access_bloom_filter_set_bit(abflcf, cidr);
            }
        }
  }
  return NGX_CONF_OK;

}
/*一些nginx中的数据结构
typedef struct {
         in_addr_t                 addr;
         in_addr_t                 mask;
       } ngx_in_cidr_t;

typedef struct {
         ngx_uint_t                family;
         union {
         ngx_in_cidr_t         in;
        #if (NGX_HAVE_INET6)
        ngx_in6_cidr_t        in6;
        #endif
        } u;
      } ngx_cidr_t;          无类域间路由
*/
