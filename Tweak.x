#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <IOKit/IOKitLib.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

static int srp_initialized = 0;

typedef struct { BIGNUM *N; BIGNUM *g; } NGConstant;

static NGConstant *new_ng(void) {
    NGConstant *ng = (NGConstant *)malloc(sizeof(NGConstant));
    ng->N = BN_new();
    ng->g = BN_new();
    BN_hex2bn(&ng->N, "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73");
    BN_hex2bn(&ng->g, "2");
    return ng;
}

static void delete_ng(NGConstant *ng) {
    if (ng) { BN_free(ng->N); BN_free(ng->g); free(ng); }
}

struct SRPUser {
    NGConstant *ng;
    BIGNUM *a;
    BIGNUM *A;
    BIGNUM *S;
    const unsigned char *bytes_A;
    int authenticated;
    const char *username;
    const unsigned char *password;
    int password_len;
    unsigned char M[CC_SHA256_DIGEST_LENGTH];
    unsigned char H_AMK[CC_SHA256_DIGEST_LENGTH];
    unsigned char session_key[CC_SHA256_DIGEST_LENGTH];
};

static void srp_init_random(void) {
    if (srp_initialized) return;
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp) {
        unsigned char buff[64];
        size_t r = fread(buff, sizeof(buff), 1, fp);
        if (r == 1) { RAND_seed(buff, sizeof(buff)); srp_initialized = 1; }
        fclose(fp);
    }
}

static BIGNUM *H_nn(const BIGNUM *n1, const BIGNUM *n2, int pad_len) {
    unsigned char buff[CC_SHA256_DIGEST_LENGTH];
    unsigned char *bin = (unsigned char *)calloc(pad_len * 2, 1);
    int len_n1 = BN_num_bytes(n1);
    int len_n2 = BN_num_bytes(n2);
    BN_bn2bin(n1, bin + (pad_len - len_n1));
    BN_bn2bin(n2, bin + pad_len + (pad_len - len_n2));
    CC_SHA256(bin, pad_len * 2, buff);
    free(bin);
    return BN_bin2bn(buff, CC_SHA256_DIGEST_LENGTH, NULL);
}

static BIGNUM *H_ns(const BIGNUM *n, const unsigned char *bytes, int len_bytes) {
    unsigned char buff[CC_SHA256_DIGEST_LENGTH];
    int len_n = BN_num_bytes(n);
    unsigned char *bin = (unsigned char *)malloc(len_n + len_bytes);
    BN_bn2bin(n, bin);
    memcpy(bin + len_n, bytes, len_bytes);
    CC_SHA256(bin, len_n + len_bytes, buff);
    free(bin);
    return BN_bin2bn(buff, CC_SHA256_DIGEST_LENGTH, NULL);
}

static BIGNUM *calculate_x(const BIGNUM *salt, const unsigned char *password, int password_len) {
    unsigned char ucp_hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    unsigned char colon = ':';
    CC_SHA256_Update(&ctx, &colon, 1);
    CC_SHA256_Update(&ctx, password, password_len);
    CC_SHA256_Final(ucp_hash, &ctx);
    return H_ns(salt, ucp_hash, CC_SHA256_DIGEST_LENGTH);
}

static void hash_num(const BIGNUM *n, unsigned char *dest) {
    int nbytes = BN_num_bytes(n);
    unsigned char *bin = (unsigned char *)malloc(nbytes);
    BN_bn2bin(n, bin);
    CC_SHA256(bin, nbytes, dest);
    free(bin);
}

static void update_hash_n(CC_SHA256_CTX *ctx, const BIGNUM *n) {
    int len = BN_num_bytes(n);
    unsigned char *bin = (unsigned char *)malloc(len);
    BN_bn2bin(n, bin);
    CC_SHA256_Update(ctx, bin, len);
    free(bin);
}

static void hash_num_padded(const BIGNUM *n, int pad_len, unsigned char *dest) {
    unsigned char *bin = (unsigned char *)calloc(pad_len, 1);
    int len = BN_num_bytes(n);
    BN_bn2bin(n, bin + (pad_len - len));
    CC_SHA256(bin, pad_len, dest);
    free(bin);
}

static void update_hash_n_padded(CC_SHA256_CTX *ctx, const BIGNUM *n, int pad_len) {
    unsigned char *bin = (unsigned char *)calloc(pad_len, 1);
    int len = BN_num_bytes(n);
    BN_bn2bin(n, bin + (pad_len - len));
    CC_SHA256_Update(ctx, bin, pad_len);
    free(bin);
}

static void calculate_M(NGConstant *ng, unsigned char *dest, const char *I, const BIGNUM *s, const BIGNUM *A, const BIGNUM *B, const unsigned char *K, int pad_len) {
    unsigned char H_N[CC_SHA256_DIGEST_LENGTH];
    unsigned char H_g[CC_SHA256_DIGEST_LENGTH];
    unsigned char H_I[CC_SHA256_DIGEST_LENGTH];
    unsigned char H_xor[CC_SHA256_DIGEST_LENGTH];
    hash_num_padded(ng->N, pad_len, H_N);
    hash_num_padded(ng->g, pad_len, H_g);
    CC_SHA256((const unsigned char *)I, strlen(I), H_I);
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) H_xor[i] = H_N[i] ^ H_g[i];
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, H_xor, CC_SHA256_DIGEST_LENGTH);
    CC_SHA256_Update(&ctx, H_I, CC_SHA256_DIGEST_LENGTH);
    update_hash_n(&ctx, s);
    update_hash_n(&ctx, A);
    update_hash_n(&ctx, B);
    CC_SHA256_Update(&ctx, K, CC_SHA256_DIGEST_LENGTH);
    CC_SHA256_Final(dest, &ctx);
}

static void calculate_H_AMK(unsigned char *dest, const BIGNUM *A, const unsigned char *M, const unsigned char *K, int pad_len) {
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    update_hash_n_padded(&ctx, A, pad_len);
    CC_SHA256_Update(&ctx, M, CC_SHA256_DIGEST_LENGTH);
    CC_SHA256_Update(&ctx, K, CC_SHA256_DIGEST_LENGTH);
    CC_SHA256_Final(dest, &ctx);
}

static struct SRPUser *srp_user_new(const char *username, const unsigned char *bytes_password, int len_password) {
    struct SRPUser *usr = (struct SRPUser *)malloc(sizeof(struct SRPUser));
    srp_init_random();
    usr->ng = new_ng();
    usr->a = BN_new();
    usr->A = BN_new();
    usr->S = BN_new();
    usr->username = strdup(username);
    usr->password = (const unsigned char *)malloc(len_password);
    memcpy((void *)usr->password, bytes_password, len_password);
    usr->password_len = len_password;
    usr->authenticated = 0;
    usr->bytes_A = NULL;
    return usr;
}

static void srp_user_set_password(struct SRPUser *usr, const unsigned char *bytes_password, int len_password) {
    if (usr->password) {
        memset((void *)usr->password, 0, usr->password_len);
        free((void *)usr->password);
    }
    usr->password = (const unsigned char *)malloc(len_password);
    memcpy((void *)usr->password, bytes_password, len_password);
    usr->password_len = len_password;
}

static void srp_user_start_authentication(struct SRPUser *usr, const unsigned char **bytes_A, int *len_A) {
    BN_CTX *ctx = BN_CTX_new();
    BN_rand(usr->a, 256, -1, 0);
    BN_mod_exp(usr->A, usr->ng->g, usr->a, usr->ng->N, ctx);
    BN_CTX_free(ctx);
    *len_A = BN_num_bytes(usr->A);
    *bytes_A = (const unsigned char *)malloc(*len_A);
    BN_bn2bin(usr->A, (unsigned char *)*bytes_A);
    usr->bytes_A = *bytes_A;
}

static void srp_user_process_challenge(struct SRPUser *usr, const unsigned char *bytes_s, int len_s, const unsigned char *bytes_B, int len_B, const unsigned char **bytes_M, int *len_M) {
    BIGNUM *s = BN_bin2bn(bytes_s, len_s, NULL);
    BIGNUM *B = BN_bin2bn(bytes_B, len_B, NULL);
    BIGNUM *v = BN_new();
    BIGNUM *tmp1 = BN_new();
    BIGNUM *tmp2 = BN_new();
    BIGNUM *tmp3 = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    *bytes_M = NULL;
    *len_M = 0;

    int nLen = BN_num_bytes(usr->ng->N);
    BIGNUM *u = H_nn(usr->A, B, nLen);
    BIGNUM *x = calculate_x(s, usr->password, usr->password_len);
    BIGNUM *k = H_nn(usr->ng->N, usr->ng->g, nLen);

    if (BN_num_bits(B) != 0 && BN_num_bits(u) != 0) {
        BN_mod_exp(v, usr->ng->g, x, usr->ng->N, ctx);
        BN_mul(tmp1, u, x, ctx);
        BN_add(tmp2, usr->a, tmp1);
        BN_mod_exp(tmp1, usr->ng->g, x, usr->ng->N, ctx);
        BN_mod_mul(tmp3, k, tmp1, usr->ng->N, ctx);
        BN_mod_sub(tmp1, B, tmp3, usr->ng->N, ctx);
        BN_mod_exp(usr->S, tmp1, tmp2, usr->ng->N, ctx);

        hash_num(usr->S, usr->session_key);
        calculate_M(usr->ng, usr->M, usr->username, s, usr->A, B, usr->session_key, BN_num_bytes(usr->ng->N));
        calculate_H_AMK(usr->H_AMK, usr->A, usr->M, usr->session_key, BN_num_bytes(usr->ng->N));

        *bytes_M = usr->M;
        *len_M = CC_SHA256_DIGEST_LENGTH;
    }

    BN_free(s); BN_free(B); BN_free(u); BN_free(x); BN_free(k);
    BN_free(v); BN_free(tmp1); BN_free(tmp2); BN_free(tmp3);
    BN_CTX_free(ctx);
}

static int srp_user_verify_session(struct SRPUser *usr, const unsigned char *bytes_HAMK) {
    if (memcmp(usr->H_AMK, bytes_HAMK, CC_SHA256_DIGEST_LENGTH) == 0) {
        usr->authenticated = 1;
        return 1;
    }
    return 0;
}

static const unsigned char *srp_user_get_session_key(struct SRPUser *usr) {
    return usr->session_key;
}

static void srp_user_delete(struct SRPUser *usr) {
    if (!usr) return;
    BN_free(usr->a);
    BN_free(usr->A);
    BN_free(usr->S);
    delete_ng(usr->ng);
    if (usr->password) { memset((void *)usr->password, 0, usr->password_len); free((void *)usr->password); }
    free((void *)usr->username);
    if (usr->bytes_A) free((void *)usr->bytes_A);
    free(usr);
}

static NSMutableDictionary *pendingTwoFactor = nil;
static NSDictionary *cachedAnisette = nil;
static NSTimeInterval cachedAnisetteFetchedAt = 0;

static NSString *base64_encode(NSData *data) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    NSUInteger length = data.length;
    const unsigned char *bytes = data.bytes;
    NSUInteger outLen = 4 * ((length + 2) / 3);
    char *out = (char *)malloc(outLen + 1);
    NSUInteger i, j;
    for (i = 0, j = 0; i < length;) {
        uint32_t octet_a = i < length ? bytes[i++] : 0;
        uint32_t octet_b = i < length ? bytes[i++] : 0;
        uint32_t octet_c = i < length ? bytes[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        out[j++] = table[(triple >> 18) & 0x3F];
        out[j++] = table[(triple >> 12) & 0x3F];
        out[j++] = table[(triple >> 6) & 0x3F];
        out[j++] = table[triple & 0x3F];
    }
    NSUInteger mod = length % 3;
    if (mod == 1) { out[outLen - 1] = '='; out[outLen - 2] = '='; }
    else if (mod == 2) { out[outLen - 1] = '='; }
    out[outLen] = '\0';
    NSString *result = [NSString stringWithUTF8String:out];
    free(out);
    return result;
}

static NSData *base64_decode(NSString *input) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char *in = [input UTF8String];
    NSUInteger inLen = strlen(in);
    while (inLen > 0 && in[inLen - 1] == '=') inLen--;
    NSUInteger outLen = (inLen * 3) / 4;
    unsigned char *out = (unsigned char *)malloc(outLen + 3);
    NSUInteger i, j = 0;
    uint32_t buffer = 0;
    int bits = 0;
    for (i = 0; i < inLen; i++) {
        const char *p = strchr(table, in[i]);
        if (!p) continue;
        int val = (int)(p - table);
        buffer = (buffer << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (buffer >> bits) & 0xFF;
        }
    }
    NSData *result = [NSData dataWithBytes:out length:j];
    free(out);
    return result;
}

static NSDictionary *fetchAnisetteFresh(void) {
    io_service_t platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    CFStringRef uuidCf = (CFStringRef)IORegistryEntryCreateCFProperty(platformExpert, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
    NSString *deviceUuid = (__bridge_transfer NSString *)uuidCf;
    IOObjectRelease(platformExpert);
    uint32_t t = (uint32_t)([[NSDate date] timeIntervalSince1970] + 180.0);
    uint8_t tbytes[4] = {(uint8_t)(t & 0xFF), (uint8_t)((t >> 8) & 0xFF), (uint8_t)((t >> 16) & 0xFF), (uint8_t)((t >> 24) & 0xFF)};
    NSString *hostAndPath = [NSString stringWithFormat:@"icloud.podpod123.com/anisette.php?%@", deviceUuid];
    NSString *secret = @"674822be7c2573ea82ff68e5579f4e5ea770b36609fe7ffe04d983de57fb9607";
    NSMutableData *round1Input = [NSMutableData dataWithBytes:tbytes length:4];
    [round1Input appendData:[hostAndPath dataUsingEncoding:NSUTF8StringEncoding]];
    [round1Input appendData:[secret dataUsingEncoding:NSUTF8StringEncoding]];
    unsigned char round1[CC_MD5_DIGEST_LENGTH];
    CC_MD5(round1Input.bytes, (CC_LONG)round1Input.length, round1);
    NSMutableData *round2Input = [NSMutableData dataWithData:[secret dataUsingEncoding:NSUTF8StringEncoding]];
    [round2Input appendBytes:round1 length:CC_MD5_DIGEST_LENGTH];
    unsigned char round2[CC_MD5_DIGEST_LENGTH];
    CC_MD5(round2Input.bytes, (CC_LONG)round2Input.length, round2);
    NSMutableString *podkeyHex = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [podkeyHex appendFormat:@"%02x", round2[i]];
    NSString *podkey = [NSString stringWithFormat:@"%u_%@", t, podkeyHex];
    const char *uuidC = [deviceUuid UTF8String];
    unsigned char pkBytes[CC_MD5_DIGEST_LENGTH];
    CC_MD5(uuidC, (CC_LONG)strlen(uuidC), pkBytes);
    NSMutableString *pk = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [pk appendFormat:@"%02x", pkBytes[i]];

    NSMutableURLRequest *anisetteReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://icloud.podpod123.com/anisette.php"]];
    [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:anisetteReq];
    [anisetteReq setValue:deviceUuid forHTTPHeaderField:@"X-Device-Uuid"];
    [anisetteReq setValue:pk forHTTPHeaderField:@"pk"];
    [anisetteReq setValue:podkey forHTTPHeaderField:@"podkey"];
    NSURLResponse *anisetteResponse = nil;
    NSError *anisetteError = nil;
    NSData *anisetteData = [NSURLConnection sendSynchronousRequest:anisetteReq returningResponse:&anisetteResponse error:&anisetteError];
    return (anisetteData && !anisetteError) ? [NSJSONSerialization JSONObjectWithData:anisetteData options:0 error:nil] : nil;
}

static NSDictionary *fetchAnisetteCached(void) {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (cachedAnisette && (now - cachedAnisetteFetchedAt) < 300) {
        return cachedAnisette;
    }
    NSDictionary *fresh = fetchAnisetteFresh();
    if (fresh) {
        cachedAnisette = fresh;
        cachedAnisetteFetchedAt = now;
    }
    return fresh;
}

static NSMutableURLRequest *buildForwardedRequest(NSURL *url, NSString *method, NSData *body, NSURLRequest *headerSource) {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:req];
    req.HTTPMethod = method;
    req.HTTPBody = body;
    for (NSString *key in headerSource.allHTTPHeaderFields) {
        [req setValue:[headerSource valueForHTTPHeaderField:key] forHTTPHeaderField:key];
    }
    return req;
}

@interface GSAPortProtocol : NSURLProtocol
@end

@implementation GSAPortProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"GSAPortHandled" inRequest:request]) return NO;
    NSString *host = request.URL.host;
    NSString *path = request.URL.path;
    if ([host isEqualToString:@"setup.icloud.com"]) {
        if ([path isEqualToString:@"/setup/login_or_create_account"]) return YES;
        if ([path isEqualToString:@"/setup/iosbuddy/loginDelegates"]) return YES;
        if ([path isEqualToString:@"/setup/get_account_settings"]) return YES;
        if ([path isEqualToString:@"/setup/authenticate/$APPLE_ID$"]) return YES;
    }
    if ([host isEqualToString:@"profile.ess.apple.com"] && [path isEqualToString:@"/WebObjects/VCProfileService.woa/wa/authenticateUser"]) return YES;
    if ([host isEqualToString:@"profile.gc.apple.com"] && [path isEqualToString:@"/WebObjects/GKProfileService.woa/wa/authenticateUser"]) return YES;
    if ([host hasSuffix:@".gc.apple.com"]) return YES;
    if ([host hasSuffix:@"fmipmobile.icloud.com"]) return YES;
    if ([host hasSuffix:@"fmfmobile.icloud.com"]) return YES;
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)stopLoading {
}

- (void)startLoading {
    if (!pendingTwoFactor) pendingTwoFactor = [NSMutableDictionary dictionary];

    NSURLRequest *request = self.request;
    NSString *path = request.URL.path;
    NSString *host = request.URL.host;
    BOOL isICloudLogin = [host isEqualToString:@"setup.icloud.com"] && [path isEqualToString:@"/setup/login_or_create_account"];
    BOOL isLoginDelegates = [host isEqualToString:@"setup.icloud.com"] && [path isEqualToString:@"/setup/iosbuddy/loginDelegates"];
    BOOL isIMFT = [host isEqualToString:@"profile.ess.apple.com"] && [path isEqualToString:@"/WebObjects/VCProfileService.woa/wa/authenticateUser"];
    BOOL isGC = [host isEqualToString:@"profile.gc.apple.com"] && [path isEqualToString:@"/WebObjects/GKProfileService.woa/wa/authenticateUser"];
    BOOL isGCGeneric = [host hasSuffix:@".gc.apple.com"] && !isGC;
    BOOL isFMIPInit = [host hasSuffix:@"fmipmobile.icloud.com"] && [path rangeOfString:@"/fmipservice/device/"].location != NSNotFound && [path hasSuffix:@"/initClient"];
    BOOL isFMIPGeneric = [host hasSuffix:@"fmipmobile.icloud.com"] && !isFMIPInit;
    BOOL isFMFGeneric = [host hasSuffix:@"fmfmobile.icloud.com"];
    BOOL isAccountSettingsDirect = [host isEqualToString:@"setup.icloud.com"] && [path isEqualToString:@"/setup/get_account_settings"];
    BOOL isBrokenAuthenticateURL = [host isEqualToString:@"setup.icloud.com"] && [path isEqualToString:@"/setup/authenticate/$APPLE_ID$"];

    if (isFMFGeneric) {
        NSOperationQueue *fmfQueue = [[NSOperationQueue alloc] init];
        [fmfQueue addOperationWithBlock:^{
            NSData *rewrittenBodyFMF = request.HTTPBody;
            if (request.HTTPBody) {
                id parsedFMF = [NSJSONSerialization JSONObjectWithData:request.HTTPBody options:0 error:nil];
                if ([parsedFMF isKindOfClass:[NSDictionary class]]) {
                    NSMutableDictionary *bodyDictFMF = [parsedFMF mutableCopy];
                    if ([bodyDictFMF[@"clientContext"] isKindOfClass:[NSDictionary class]]) {
                        NSMutableDictionary *clientContextFMF = [bodyDictFMF[@"clientContext"] mutableCopy];
                        clientContextFMF[@"osVersion"] = @"7.0";
                        clientContextFMF[@"appVersion"] = @"3.0";
                        bodyDictFMF[@"clientContext"] = clientContextFMF;
                    }
                    [bodyDictFMF removeObjectForKey:@"serverContext"];
                    NSData *reserializedFMF = [NSJSONSerialization dataWithJSONObject:bodyDictFMF options:0 error:nil];
                    if (reserializedFMF) rewrittenBodyFMF = reserializedFMF;
                }
            }

            NSMutableURLRequest *reqFMF = buildForwardedRequest(request.URL, request.HTTPMethod, rewrittenBodyFMF, request);

            NSURLResponse *responseFMF = nil;
            NSError *errorFMF = nil;
            NSData *dataFMF = [NSURLConnection sendSynchronousRequest:reqFMF returningResponse:&responseFMF error:&errorFMF];
            NSHTTPURLResponse *httpResponseFMF = (NSHTTPURLResponse *)responseFMF;
            if (!httpResponseFMF && dataFMF) {
                httpResponseFMF = [[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            }

            if (!dataFMF) {
                NSHTTPURLResponse *failResponseFMF = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:502 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponseFMF cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            if (dataFMF) {
                id parsedResp = [NSJSONSerialization JSONObjectWithData:dataFMF options:0 error:nil];
                if ([parsedResp isKindOfClass:[NSDictionary class]]) {
                    NSMutableDictionary *respDict = [parsedResp mutableCopy];
                    if ([respDict[@"serverContext"] isKindOfClass:[NSDictionary class]]) {
                        NSMutableDictionary *sc = [respDict[@"serverContext"] mutableCopy];
                        [sc removeObjectForKey:@"authToken"];
                        [sc removeObjectForKey:@"notificationToken"];
                        respDict[@"serverContext"] = sc;
                        NSData *modifiedResp = [NSJSONSerialization dataWithJSONObject:respDict options:0 error:nil];
                        if (modifiedResp) dataFMF = modifiedResp;
                    }
                }
            }

            [self.client URLProtocol:self didReceiveResponse:httpResponseFMF cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:dataFMF];
            [self.client URLProtocolDidFinishLoading:self];
        }];
        return;
    }

    if (isAccountSettingsDirect) {
        NSOperationQueue *asQueue = [[NSOperationQueue alloc] init];
        [asQueue addOperationWithBlock:^{
            BOOL tokenNeedsMD = NO;
            NSString *authHeaderAS = [request valueForHTTPHeaderField:@"Authorization"];
            if ([authHeaderAS hasPrefix:@"Basic "]) {
                NSData *decodedAS = base64_decode([authHeaderAS substringFromIndex:6]);
                NSString *decodedStrAS = [[NSString alloc] initWithData:decodedAS encoding:NSUTF8StringEncoding];
                NSRange colonRangeAS = [decodedStrAS rangeOfString:@":"];
                if (colonRangeAS.location != NSNotFound) {
                    NSString *tokenAS = [decodedStrAS substringFromIndex:colonRangeAS.location + 1];
                    if ([tokenAS hasPrefix:@"E"]) tokenNeedsMD = YES;
                }
            }

            NSDictionary *cpdAS = tokenNeedsMD ? fetchAnisetteCached() : nil;

            NSMutableURLRequest *reqAS = buildForwardedRequest(request.URL, request.HTTPMethod, request.HTTPBody, request);
            if (cpdAS) { for (NSString *key in cpdAS) [reqAS setValue:cpdAS[key] forHTTPHeaderField:key]; }

            NSURLResponse *responseAS = nil;
            NSError *errorAS = nil;
            NSData *dataAS = [NSURLConnection sendSynchronousRequest:reqAS returningResponse:&responseAS error:&errorAS];
            NSHTTPURLResponse *httpResponseAS = (NSHTTPURLResponse *)responseAS;
            if (!httpResponseAS && dataAS) {
                httpResponseAS = [[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            }

            if (!dataAS) {
                NSHTTPURLResponse *failResponseAS = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:502 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponseAS cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            [self.client URLProtocol:self didReceiveResponse:httpResponseAS cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:dataAS];
            [self.client URLProtocolDidFinishLoading:self];
        }];
        return;
    }

    if (isFMIPGeneric) {
        NSOperationQueue *refreshQueue = [[NSOperationQueue alloc] init];
        [refreshQueue addOperationWithBlock:^{
            NSData *rewrittenBodyR = request.HTTPBody;
            if (request.HTTPBody) {
                id parsedR = [NSJSONSerialization JSONObjectWithData:request.HTTPBody options:0 error:nil];
                if ([parsedR isKindOfClass:[NSDictionary class]]) {
                    NSMutableDictionary *bodyDictR = [parsedR mutableCopy];
                    if ([bodyDictR[@"clientContext"] isKindOfClass:[NSDictionary class]]) {
                        NSMutableDictionary *clientContextR = [bodyDictR[@"clientContext"] mutableCopy];
                        clientContextR[@"osVersion"] = @"9.0";
                        clientContextR[@"appVersion"] = @"5.0";
                        bodyDictR[@"clientContext"] = clientContextR;
                        NSData *reserializedR = [NSJSONSerialization dataWithJSONObject:bodyDictR options:0 error:nil];
                        if (reserializedR) rewrittenBodyR = reserializedR;
                    }
                }
            }

            NSMutableURLRequest *reqR = buildForwardedRequest(request.URL, request.HTTPMethod, rewrittenBodyR, request);
            if ([request valueForHTTPHeaderField:@"X-Apple-Find-API-Ver"]) {
                [reqR setValue:@"3.0" forHTTPHeaderField:@"X-Apple-Find-API-Ver"];
            }

            NSURLResponse *responseR = nil;
            NSError *errorR = nil;
            NSData *dataR = [NSURLConnection sendSynchronousRequest:reqR returningResponse:&responseR error:&errorR];
            NSHTTPURLResponse *httpResponseR = (NSHTTPURLResponse *)responseR;
            if (!httpResponseR && dataR) {
                httpResponseR = [[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            }

            if (!dataR) {
                NSHTTPURLResponse *failResponseR = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:502 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponseR cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            [self.client URLProtocol:self didReceiveResponse:httpResponseR cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:dataR];
            [self.client URLProtocolDidFinishLoading:self];
        }];
        return;
    }

    if (isGCGeneric) {
        NSOperationQueue *gcQueue = [[NSOperationQueue alloc] init];
        [gcQueue addOperationWithBlock:^{
            NSMutableURLRequest *reqF = buildForwardedRequest(request.URL, request.HTTPMethod, request.HTTPBody, request);

            NSURLResponse *responseF = nil;
            NSError *errorF = nil;
            NSData *dataF = [NSURLConnection sendSynchronousRequest:reqF returningResponse:&responseF error:&errorF];
            NSHTTPURLResponse *httpResponseF = (NSHTTPURLResponse *)responseF;
            if (!httpResponseF && dataF) {
                httpResponseF = [[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            }

            if (!dataF) {
                NSHTTPURLResponse *failResponseF = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:502 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponseF cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            [self.client URLProtocol:self didReceiveResponse:httpResponseF cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:dataF];
            [self.client URLProtocolDidFinishLoading:self];
        }];
        return;
    }

    NSString *username = nil;
    NSString *submittedPassword = nil;
    NSData *originalBody = request.HTTPBody;

    if (isICloudLogin || isFMIPInit || isBrokenAuthenticateURL) {
        NSString *authHeader = [request valueForHTTPHeaderField:@"Authorization"];
        if ([authHeader hasPrefix:@"Basic "]) {
            NSData *decoded = base64_decode([authHeader substringFromIndex:6]);
            NSString *decodedStr = [[NSString alloc] initWithData:decoded encoding:NSUTF8StringEncoding];
            NSRange colonRange = [decodedStr rangeOfString:@":"];
            if (colonRange.location != NSNotFound) {
                username = [decodedStr substringToIndex:colonRange.location];
                submittedPassword = [decodedStr substringFromIndex:colonRange.location + 1];
            }
        }
    } else {
        NSDictionary *bodyDict = [NSPropertyListSerialization propertyListWithData:originalBody options:0 format:NULL error:nil];
        username = bodyDict[isLoginDelegates ? @"apple-id" : @"username"];
        submittedPassword = bodyDict[@"password"];
    }

    if (!username || !submittedPassword) {
        NSHTTPURLResponse *response400 = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:400 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
        [self.client URLProtocol:self didReceiveResponse:response400 cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        [self.client URLProtocolDidFinishLoading:self];
        return;
    }

    if (isFMIPInit && username.length > 0 && [username rangeOfCharacterFromSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]].location == NSNotFound) {
        NSOperationQueue *cachedQueue = [[NSOperationQueue alloc] init];
        [cachedQueue addOperationWithBlock:^{
            NSData *rewrittenBodyC = originalBody;
            if (originalBody) {
                id parsedC = [NSJSONSerialization JSONObjectWithData:originalBody options:0 error:nil];
                if ([parsedC isKindOfClass:[NSDictionary class]]) {
                    NSMutableDictionary *bodyDictC = [parsedC mutableCopy];
                    if ([bodyDictC[@"clientContext"] isKindOfClass:[NSDictionary class]]) {
                        NSMutableDictionary *clientContextC = [bodyDictC[@"clientContext"] mutableCopy];
                        clientContextC[@"osVersion"] = @"9.0";
                        clientContextC[@"appVersion"] = @"5.0";
                        bodyDictC[@"clientContext"] = clientContextC;
                        NSData *reserializedC = [NSJSONSerialization dataWithJSONObject:bodyDictC options:0 error:nil];
                        if (reserializedC) rewrittenBodyC = reserializedC;
                    }
                }
            }

            NSMutableURLRequest *reqC = buildForwardedRequest(request.URL, request.HTTPMethod, rewrittenBodyC, request);
            if ([request valueForHTTPHeaderField:@"X-Apple-Find-API-Ver"]) {
                [reqC setValue:@"3.0" forHTTPHeaderField:@"X-Apple-Find-API-Ver"];
            }

            NSURLResponse *responseC = nil;
            NSError *errorC = nil;
            NSData *dataC = [NSURLConnection sendSynchronousRequest:reqC returningResponse:&responseC error:&errorC];
            NSHTTPURLResponse *httpResponseC = (NSHTTPURLResponse *)responseC;
            if (!httpResponseC && dataC) {
                httpResponseC = [[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            }

            if (!dataC) {
                NSHTTPURLResponse *failResponseC = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:502 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponseC cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            [self.client URLProtocol:self didReceiveResponse:httpResponseC cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:dataC];
            [self.client URLProtocolDidFinishLoading:self];
        }];
        return;
    }

    NSDictionary *pending = pendingTwoFactor[username];
    NSString *trailingCode = nil;
    if (pending && submittedPassword.length == 6 && [submittedPassword rangeOfCharacterFromSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]].location == NSNotFound) {
        trailingCode = submittedPassword;
    }

    NSString *realPassword = trailingCode ? pending[@"password"] : submittedPassword;

    NSOperationQueue *queue = [[NSOperationQueue alloc] init];
    [queue addOperationWithBlock:^{

        if (trailingCode) {
            NSDictionary *pend = pendingTwoFactor[username];
            NSString *combined = [NSString stringWithFormat:@"%@:%@", pend[@"dsid"], pend[@"idmsToken"]];
            NSString *identityToken = base64_encode([combined dataUsingEncoding:NSUTF8StringEncoding]);

            NSDictionary *submitCpd = fetchAnisetteFresh();

            NSMutableURLRequest *submitReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://gsa.apple.com/grandslam/GsService2/validate"]];
            [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:submitReq];
            [submitReq setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Content-Type"];
            [submitReq setValue:@"akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0" forHTTPHeaderField:@"User-Agent"];
            [submitReq setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Accept"];
            [submitReq setValue:@"en-us" forHTTPHeaderField:@"Accept-Language"];
            [submitReq setValue:identityToken forHTTPHeaderField:@"X-Apple-Identity-Token"];
            [submitReq setValue:@"com.apple.gs.xcode.auth" forHTTPHeaderField:@"X-Apple-App-Info"];
            [submitReq setValue:@"11.2 (11B41)" forHTTPHeaderField:@"X-Xcode-Version"];
            [submitReq setValue:trailingCode forHTTPHeaderField:@"security-code"];
            [submitReq setValue:@"<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>" forHTTPHeaderField:@"X-Mme-Client-Info"];
            if (submitCpd) { for (NSString *key in submitCpd) [submitReq setValue:submitCpd[key] forHTTPHeaderField:key]; }
            NSURLResponse *submitResponse = nil;
            NSError *submitError = nil;
            [NSURLConnection sendSynchronousRequest:submitReq returningResponse:&submitResponse error:&submitError];
            NSHTTPURLResponse *submitHttp = (NSHTTPURLResponse *)submitResponse;

            if (submitHttp.statusCode != 200) {
                NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }
            [pendingTwoFactor removeObjectForKey:username];
        }

        NSDictionary *cpd = fetchAnisetteFresh();

        if (!cpd) {
            NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        struct SRPUser *usr = srp_user_new([username UTF8String], (const unsigned char *)"", 0);
        const unsigned char *bytesA = NULL;
        int lenA = 0;
        srp_user_start_authentication(usr, &bytesA, &lenA);
        NSData *aData = [NSData dataWithBytes:bytesA length:lenA];

        NSMutableDictionary *initInner = [NSMutableDictionary dictionaryWithDictionary:@{@"A2k": aData, @"ps": @[@"s2k", @"s2k_fo"], @"u": username, @"o": @"init"}];
        initInner[@"cpd"] = cpd;
        NSData *initPlistData = [NSPropertyListSerialization dataWithPropertyList:@{@"Header": @{@"Version": @"1.0.1"}, @"Request": initInner} format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
        NSMutableURLRequest *initReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://gsa.apple.com/grandslam/GsService2"]];
        [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:initReq];
        initReq.HTTPMethod = @"POST";
        initReq.HTTPBody = initPlistData;
        [initReq setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Content-Type"];
        [initReq setValue:@"*/*" forHTTPHeaderField:@"Accept"];
        [initReq setValue:@"akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0" forHTTPHeaderField:@"User-Agent"];
        [initReq setValue:@"<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>" forHTTPHeaderField:@"X-Mme-Client-Info"];
        [initReq setValue:cpd[@"X-Apple-I-MD-M"] forHTTPHeaderField:@"X-Apple-I-MD-M"];
        [initReq setValue:cpd[@"X-Mme-Device-Id"] forHTTPHeaderField:@"X-Mme-Device-Id"];
        NSURLResponse *initResponse = nil;
        NSError *initError = nil;
        NSData *initData = [NSURLConnection sendSynchronousRequest:initReq returningResponse:&initResponse error:&initError];
        NSDictionary *initResp = initData ? [NSPropertyListSerialization propertyListWithData:initData options:0 format:NULL error:nil][@"Response"] : nil;

        if (!initResp || !initResp[@"sp"]) {
            srp_user_delete(usr);
            NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        NSData *salt = initResp[@"s"];
        NSInteger iterations = [initResp[@"i"] integerValue];
        NSString *protocol = initResp[@"sp"];
        NSData *bData = initResp[@"B"];
        NSString *continuation = initResp[@"c"];

        unsigned char shaDigest[CC_SHA256_DIGEST_LENGTH];
        const char *pwUTF8 = [realPassword UTF8String];
        CC_SHA256(pwUTF8, (CC_LONG)strlen(pwUTF8), shaDigest);
        NSData *pInput;
        if ([protocol isEqualToString:@"s2k_fo"]) {
            NSMutableString *hex = [NSMutableString string];
            for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", shaDigest[i]];
            pInput = [hex dataUsingEncoding:NSUTF8StringEncoding];
        } else {
            pInput = [NSData dataWithBytes:shaDigest length:CC_SHA256_DIGEST_LENGTH];
        }
        unsigned char derivedKey[32];
        CCKeyDerivationPBKDF(kCCPBKDF2, pInput.bytes, pInput.length, salt.bytes, salt.length, kCCPRFHmacAlgSHA256, (uint)iterations, derivedKey, sizeof(derivedKey));
        srp_user_set_password(usr, derivedKey, sizeof(derivedKey));

        const unsigned char *bytesM = NULL;
        int lenM = 0;
        srp_user_process_challenge(usr, salt.bytes, (int)salt.length, bData.bytes, (int)bData.length, &bytesM, &lenM);
        if (!bytesM) {
            srp_user_delete(usr);
            NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }
        NSData *mData = [NSData dataWithBytes:bytesM length:lenM];

        NSMutableDictionary *completeInner = [NSMutableDictionary dictionaryWithDictionary:@{@"c": continuation, @"M1": mData, @"u": username, @"o": @"complete"}];
        completeInner[@"cpd"] = cpd;
        NSData *completePlistData = [NSPropertyListSerialization dataWithPropertyList:@{@"Header": @{@"Version": @"1.0.1"}, @"Request": completeInner} format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
        NSDictionary *cpdComplete = fetchAnisetteFresh() ?: cpd;

        NSMutableURLRequest *completeReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://gsa.apple.com/grandslam/GsService2"]];
        [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:completeReq];
        completeReq.HTTPMethod = @"POST";
        completeReq.HTTPBody = completePlistData;
        [completeReq setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Content-Type"];
        [completeReq setValue:@"*/*" forHTTPHeaderField:@"Accept"];
        [completeReq setValue:@"akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0" forHTTPHeaderField:@"User-Agent"];
        [completeReq setValue:@"<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>" forHTTPHeaderField:@"X-Mme-Client-Info"];
        [completeReq setValue:cpdComplete[@"X-Apple-I-MD-M"] forHTTPHeaderField:@"X-Apple-I-MD-M"];
        [completeReq setValue:cpdComplete[@"X-Mme-Device-Id"] forHTTPHeaderField:@"X-Mme-Device-Id"];
        NSURLResponse *completeResponse = nil;
        NSError *completeError = nil;
        NSData *completeData = [NSURLConnection sendSynchronousRequest:completeReq returningResponse:&completeResponse error:&completeError];
        NSDictionary *completeResp = completeData ? [NSPropertyListSerialization propertyListWithData:completeData options:0 format:NULL error:nil][@"Response"] : nil;

        if (!completeResp) {
            srp_user_delete(usr);
            NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        NSData *m2Data = completeResp[@"M2"];
        if (!m2Data) {
            srp_user_delete(usr);
            NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }
        if (!srp_user_verify_session(usr, m2Data.bytes)) {
            srp_user_delete(usr);
            NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        NSData *sessionKey = [NSData dataWithBytes:srp_user_get_session_key(usr) length:CC_SHA256_DIGEST_LENGTH];
        srp_user_delete(usr);

        unsigned char extraKeyMac[CC_SHA256_DIGEST_LENGTH];
        unsigned char extraIvMac[CC_SHA256_DIGEST_LENGTH];
        NSData *keyLabel = [@"extra data key:" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *ivLabel = [@"extra data iv:" dataUsingEncoding:NSUTF8StringEncoding];
        CCHmac(kCCHmacAlgSHA256, sessionKey.bytes, sessionKey.length, keyLabel.bytes, keyLabel.length, extraKeyMac);
        CCHmac(kCCHmacAlgSHA256, sessionKey.bytes, sessionKey.length, ivLabel.bytes, ivLabel.length, extraIvMac);

        NSData *spdEncrypted = completeResp[@"spd"];
        size_t outLen = 0;
        NSMutableData *outData = [NSMutableData dataWithLength:spdEncrypted.length + kCCBlockSizeAES128];
        CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding, extraKeyMac, CC_SHA256_DIGEST_LENGTH, extraIvMac, spdEncrypted.bytes, spdEncrypted.length, outData.mutableBytes, outData.length, &outLen);
        if (cryptStatus != kCCSuccess) {
            NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }
        NSData *rawSpd = [outData subdataWithRange:NSMakeRange(0, outLen)];

        NSMutableData *wrapped = [NSMutableData data];
        [wrapped appendData:[@"<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\">" dataUsingEncoding:NSUTF8StringEncoding]];
        [wrapped appendData:rawSpd];
        [wrapped appendData:[@"</plist>" dataUsingEncoding:NSUTF8StringEncoding]];
        NSDictionary *spd = [NSPropertyListSerialization propertyListWithData:wrapped options:0 format:NULL error:nil];

        if (!spd) {
            NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        NSDictionary *statusDict = completeResp[@"Status"];
        NSInteger hsc = [statusDict[@"hsc"] integerValue];

        if (hsc != 200) {
            NSString *au = statusDict[@"au"];
            if ([au isEqualToString:@"trustedDeviceSecondaryAuth"] || [au isEqualToString:@"secondaryAuth"]) {
                NSString *dsid2fa = spd[@"adsid"];
                NSString *idmsToken2fa = spd[@"GsIdmsToken"];
                NSString *combined2fa = [NSString stringWithFormat:@"%@:%@", dsid2fa, idmsToken2fa];
                NSString *identityToken2fa = base64_encode([combined2fa dataUsingEncoding:NSUTF8StringEncoding]);

                NSDictionary *triggerCpd = fetchAnisetteFresh();

                NSMutableURLRequest *triggerReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://gsa.apple.com/auth/verify/trusteddevice"]];
                [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:triggerReq];
                [triggerReq setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Content-Type"];
                [triggerReq setValue:@"akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0" forHTTPHeaderField:@"User-Agent"];
                [triggerReq setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Accept"];
                [triggerReq setValue:@"en-us" forHTTPHeaderField:@"Accept-Language"];
                [triggerReq setValue:identityToken2fa forHTTPHeaderField:@"X-Apple-Identity-Token"];
                [triggerReq setValue:@"com.apple.gs.xcode.auth" forHTTPHeaderField:@"X-Apple-App-Info"];
                [triggerReq setValue:@"11.2 (11B41)" forHTTPHeaderField:@"X-Xcode-Version"];
                [triggerReq setValue:@"<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>" forHTTPHeaderField:@"X-Mme-Client-Info"];
                if (triggerCpd) { for (NSString *key in triggerCpd) [triggerReq setValue:triggerCpd[key] forHTTPHeaderField:key]; }
                NSURLResponse *triggerResponse = nil;
                NSError *triggerError = nil;
                [NSURLConnection sendSynchronousRequest:triggerReq returningResponse:&triggerResponse error:&triggerError];

                pendingTwoFactor[username] = @{@"password": realPassword, @"dsid": dsid2fa ?: @"", @"idmsToken": idmsToken2fa ?: @""};
                NSHTTPURLResponse *needCodeResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:needCodeResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        NSString *pet = spd[@"t"][@"com.apple.gs.idms.pet"][@"token"];
        NSString *adsid = spd[@"adsid"];

        if (isBrokenAuthenticateURL) {
            NSString *identityFix = base64_encode([[NSString stringWithFormat:@"%@:%@", username, pet] dataUsingEncoding:NSUTF8StringEncoding]);
            NSMutableURLRequest *authReqFix = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"https://setup.icloud.com/setup/authenticate/%@", username]]];
            [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:authReqFix];
            [authReqFix setValue:[NSString stringWithFormat:@"Basic %@", identityFix] forHTTPHeaderField:@"Authorization"];

            NSURLResponse *responseFix = nil;
            NSError *errorFix = nil;
            NSData *dataFix = [NSURLConnection sendSynchronousRequest:authReqFix returningResponse:&responseFix error:&errorFix];
            NSHTTPURLResponse *httpResponseFix = (NSHTTPURLResponse *)responseFix;
            if (!httpResponseFix && dataFix) {
                httpResponseFix = [[NSHTTPURLResponse alloc] initWithURL:authReqFix.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            }

            if (!dataFix) {
                NSHTTPURLResponse *failResponseFix = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:502 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponseFix cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            [self.client URLProtocol:self didReceiveResponse:httpResponseFix cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:dataFix];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        if (isICloudLogin) {
            NSString *identity1 = base64_encode([[NSString stringWithFormat:@"%@:%@", username, pet] dataUsingEncoding:NSUTF8StringEncoding]);

            NSMutableURLRequest *authReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"https://setup.icloud.com/setup/authenticate/%@", username]]];
            [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:authReq];
            [authReq setValue:[NSString stringWithFormat:@"Basic %@", identity1] forHTTPHeaderField:@"Authorization"];

            NSURLResponse *authResponse = nil;
            NSError *authError = nil;
            NSData *authData = [NSURLConnection sendSynchronousRequest:authReq returningResponse:&authResponse error:&authError];

            NSString *dsid = nil;
            NSString *mmeAuthToken = nil;
            if (authData) {
                NSDictionary *parsed = [NSPropertyListSerialization propertyListWithData:authData options:0 format:NULL error:nil];
                dsid = parsed[@"appleAccountInfo"][@"dsid"];
                mmeAuthToken = parsed[@"tokens"][@"mmeAuthToken"];
            }

            if (!dsid || !mmeAuthToken) {
                NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            NSString *identity2 = base64_encode([[NSString stringWithFormat:@"%@:%@", dsid, mmeAuthToken] dataUsingEncoding:NSUTF8StringEncoding]);

            NSMutableURLRequest *settingsReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://setup.icloud.com/setup/get_account_settings"]];
            [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:settingsReq];
            settingsReq.HTTPMethod = @"POST";
            [settingsReq setValue:[NSString stringWithFormat:@"Basic %@", identity2] forHTTPHeaderField:@"Authorization"];
            [settingsReq setValue:[self.request valueForHTTPHeaderField:@"X-Mme-Client-Info"] forHTTPHeaderField:@"X-Mme-Client-Info"];
            [settingsReq setValue:[self.request valueForHTTPHeaderField:@"User-Agent"] forHTTPHeaderField:@"User-Agent"];
            [settingsReq setValue:[self.request valueForHTTPHeaderField:@"X-Apns-Token"] forHTTPHeaderField:@"X-APNS-Token"];
            [settingsReq setValue:@"US" forHTTPHeaderField:@"X-Mme-Country"];
            [settingsReq setValue:@"PDT" forHTTPHeaderField:@"X-Mme-Timezone"];
            [settingsReq setValue:@"false" forHTTPHeaderField:@"X-Aos-Accept-Tos"];
            [settingsReq setValue:@"en-us" forHTTPHeaderField:@"Accept-Language"];
            [settingsReq setValue:@"*/*" forHTTPHeaderField:@"Accept"];

            NSURLResponse *settingsResponse = nil;
            NSError *settingsError = nil;
            NSData *settingsData = [NSURLConnection sendSynchronousRequest:settingsReq returningResponse:&settingsResponse error:&settingsError];
            NSHTTPURLResponse *settingsHttp = (NSHTTPURLResponse *)settingsResponse;

            if (!settingsData) {
                NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:502 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            [self.client URLProtocol:self didReceiveResponse:settingsHttp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:settingsData];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        if (isLoginDelegates) {
            NSMutableDictionary *substitutedDict = [[NSPropertyListSerialization propertyListWithData:originalBody options:0 format:NULL error:nil] mutableCopy];
            substitutedDict[@"apple-id"] = adsid;
            substitutedDict[@"password"] = pet;
            NSData *substituted = [NSPropertyListSerialization dataWithPropertyList:substitutedDict format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];

            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://setup.icloud.com/setup/iosbuddy/loginDelegates"]];
            [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:req];
            req.HTTPMethod = @"POST";
            req.HTTPBody = substituted;
            [req setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Content-Type"];
            [req setValue:[self.request valueForHTTPHeaderField:@"X-Mme-Client-Info"] forHTTPHeaderField:@"X-Mme-Client-Info"];
            [req setValue:[self.request valueForHTTPHeaderField:@"User-Agent"] forHTTPHeaderField:@"User-Agent"];
            [req setValue:[self.request valueForHTTPHeaderField:@"X-Apns-Token"] forHTTPHeaderField:@"X-APNS-Token"];
            [req setValue:@"US" forHTTPHeaderField:@"X-Mme-Country"];
            [req setValue:@"PDT" forHTTPHeaderField:@"X-Mme-Timezone"];
            [req setValue:@"en-us" forHTTPHeaderField:@"Accept-Language"];
            [req setValue:@"*/*" forHTTPHeaderField:@"Accept"];

            NSURLResponse *response = nil;
            NSError *error = nil;
            NSData *data = [NSURLConnection sendSynchronousRequest:req returningResponse:&response error:&error];
            NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
            if (!httpResponse && data) {
                httpResponse = [[NSHTTPURLResponse alloc] initWithURL:req.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            }

            if (!data) {
                NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:502 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            NSMutableDictionary *delegatesRespDict = [[NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:nil] mutableCopy];
            NSDictionary *delegatesDict = delegatesRespDict[@"delegates"];
            NSDictionary *mobilemeDict = [delegatesDict isKindOfClass:[NSDictionary class]] ? delegatesDict[@"com.apple.mobileme"] : nil;
            BOOL mobilemeHasTokens = [mobilemeDict isKindOfClass:[NSDictionary class]] && [mobilemeDict[@"tokens"] isKindOfClass:[NSDictionary class]];

            if (mobilemeHasTokens) {
                NSString *identityAuthLD = base64_encode([[NSString stringWithFormat:@"%@:%@", username, pet] dataUsingEncoding:NSUTF8StringEncoding]);
                NSMutableURLRequest *authReqLD = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"https://setup.icloud.com/setup/authenticate/%@", username]]];
                [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:authReqLD];
                [authReqLD setValue:[NSString stringWithFormat:@"Basic %@", identityAuthLD] forHTTPHeaderField:@"Authorization"];

                NSURLResponse *authResponseLD = nil;
                NSError *authErrorLD = nil;
                NSData *authDataLD = [NSURLConnection sendSynchronousRequest:authReqLD returningResponse:&authResponseLD error:&authErrorLD];

                NSString *oldDsid = nil;
                NSString *oldStyleToken = nil;
                if (authDataLD) {
                    NSDictionary *parsedAuthLD = [NSPropertyListSerialization propertyListWithData:authDataLD options:0 format:NULL error:nil];
                    oldDsid = parsedAuthLD[@"appleAccountInfo"][@"dsid"];
                    oldStyleToken = parsedAuthLD[@"tokens"][@"mmeAuthToken"];
                }

                if (oldDsid && oldStyleToken) {
                    NSString *identitySettingsLD = base64_encode([[NSString stringWithFormat:@"%@:%@", oldDsid, oldStyleToken] dataUsingEncoding:NSUTF8StringEncoding]);
                    NSMutableURLRequest *settingsReqLD = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://setup.icloud.com/setup/get_account_settings"]];
                    [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:settingsReqLD];
                    settingsReqLD.HTTPMethod = @"POST";
                    [settingsReqLD setValue:[NSString stringWithFormat:@"Basic %@", identitySettingsLD] forHTTPHeaderField:@"Authorization"];
                    [settingsReqLD setValue:[self.request valueForHTTPHeaderField:@"X-Mme-Client-Info"] forHTTPHeaderField:@"X-Mme-Client-Info"];
                    [settingsReqLD setValue:[self.request valueForHTTPHeaderField:@"User-Agent"] forHTTPHeaderField:@"User-Agent"];
                    [settingsReqLD setValue:@"US" forHTTPHeaderField:@"X-Mme-Country"];
                    [settingsReqLD setValue:@"PDT" forHTTPHeaderField:@"X-Mme-Timezone"];
                    [settingsReqLD setValue:@"false" forHTTPHeaderField:@"X-Aos-Accept-Tos"];
                    [settingsReqLD setValue:@"en-us" forHTTPHeaderField:@"Accept-Language"];
                    [settingsReqLD setValue:@"*/*" forHTTPHeaderField:@"Accept"];

                    NSURLResponse *settingsResponseLD = nil;
                    NSError *settingsErrorLD = nil;
                    NSData *settingsDataLD = [NSURLConnection sendSynchronousRequest:settingsReqLD returningResponse:&settingsResponseLD error:&settingsErrorLD];

                    NSDictionary *replacementTokens = nil;
                    if (settingsDataLD) {
                        NSDictionary *parsedSettingsLD = [NSPropertyListSerialization propertyListWithData:settingsDataLD options:0 format:NULL error:nil];
                        if ([parsedSettingsLD[@"tokens"] isKindOfClass:[NSDictionary class]]) {
                            replacementTokens = parsedSettingsLD[@"tokens"];
                        }
                    }

                    if (replacementTokens) {
                        NSMutableDictionary *mutableDelegates = [delegatesDict mutableCopy];
                        NSMutableDictionary *mutableMobileme = [mobilemeDict mutableCopy];
                        mutableMobileme[@"tokens"] = replacementTokens;
                        mutableDelegates[@"com.apple.mobileme"] = mutableMobileme;
                        delegatesRespDict[@"delegates"] = mutableDelegates;
                        NSData *modifiedDelegatesData = [NSPropertyListSerialization dataWithPropertyList:delegatesRespDict format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
                        if (modifiedDelegatesData) data = modifiedDelegatesData;
                    }
                }
            }

            [self.client URLProtocol:self didReceiveResponse:httpResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:data];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        if (isIMFT || isGC) {
            NSMutableDictionary *substitutedDict = [[NSPropertyListSerialization propertyListWithData:originalBody options:0 format:NULL error:nil] mutableCopy];
            substitutedDict[@"username"] = adsid;
            substitutedDict[@"password"] = pet;
            NSData *substituted = [NSPropertyListSerialization dataWithPropertyList:substitutedDict format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];

            NSString *urlStr = isIMFT ? @"https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser" : @"https://profile.gc.apple.com/WebObjects/GKProfileService.woa/wa/authenticateUser";

            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
            [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:req];
            req.HTTPMethod = @"POST";
            req.HTTPBody = substituted;

            for (NSString *key in self.request.allHTTPHeaderFields) {
                NSString *lower = [key lowercaseString];
                if (![lower isEqualToString:@"host"] && ![lower isEqualToString:@"content-length"] && ![lower isEqualToString:@"content-encoding"]) {
                    [req setValue:[self.request valueForHTTPHeaderField:key] forHTTPHeaderField:key];
                }
            }
            if (![req valueForHTTPHeaderField:@"Content-Type"]) {
                [req setValue:@"application/x-apple-plist" forHTTPHeaderField:@"Content-Type"];
            }

            NSURLResponse *response = nil;
            NSError *error = nil;
            NSData *data = [NSURLConnection sendSynchronousRequest:req returningResponse:&response error:&error];
            NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
            if (!httpResponse && data) {
                httpResponse = [[NSHTTPURLResponse alloc] initWithURL:req.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            }

            if (!data) {
                NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:502 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            NSMutableDictionary *outHeaders = [NSMutableDictionary dictionary];
            if (httpResponse.allHeaderFields[@"Content-Type"]) outHeaders[@"Content-Type"] = httpResponse.allHeaderFields[@"Content-Type"];
            if (httpResponse.allHeaderFields[@"Content-Encoding"]) outHeaders[@"Content-Encoding"] = httpResponse.allHeaderFields[@"Content-Encoding"];

            NSHTTPURLResponse *okResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:httpResponse.statusCode HTTPVersion:@"HTTP/1.1" headerFields:outHeaders];
            [self.client URLProtocol:self didReceiveResponse:okResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:data];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        if (isFMIPInit) {
            NSMutableDictionary *bodyDict = [[NSJSONSerialization JSONObjectWithData:originalBody options:0 error:nil] mutableCopy];
            NSMutableDictionary *clientContext = [bodyDict[@"clientContext"] mutableCopy];
            clientContext[@"osVersion"] = @"9.0";
            clientContext[@"appVersion"] = @"5.0";
            bodyDict[@"clientContext"] = clientContext;
            NSData *rewrittenBody = [NSJSONSerialization dataWithJSONObject:bodyDict options:0 error:nil];

            NSString *identityFMIP = base64_encode([[NSString stringWithFormat:@"%@:%@", adsid, pet] dataUsingEncoding:NSUTF8StringEncoding]);

            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:request.URL];
            [NSURLProtocol setProperty:@YES forKey:@"GSAPortHandled" inRequest:req];
            req.HTTPMethod = request.HTTPMethod;
            req.HTTPBody = rewrittenBody;
            for (NSString *key in request.allHTTPHeaderFields) {
                [req setValue:[request valueForHTTPHeaderField:key] forHTTPHeaderField:key];
            }
            [req setValue:[NSString stringWithFormat:@"Basic %@", identityFMIP] forHTTPHeaderField:@"Authorization"];
            if ([request valueForHTTPHeaderField:@"X-Apple-Find-API-Ver"]) {
                [req setValue:@"3.0" forHTTPHeaderField:@"X-Apple-Find-API-Ver"];
            }

            NSURLResponse *response = nil;
            NSError *error = nil;
            NSData *data = [NSURLConnection sendSynchronousRequest:req returningResponse:&response error:&error];
            NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
            if (!httpResponse && data) {
                httpResponse = [[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
            }

            if (!data) {
                NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:502 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
                [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
                [self.client URLProtocolDidFinishLoading:self];
                return;
            }

            [self.client URLProtocol:self didReceiveResponse:httpResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:data];
            [self.client URLProtocolDidFinishLoading:self];
            return;
        }

        NSHTTPURLResponse *failResponse = [[NSHTTPURLResponse alloc] initWithURL:self.request.URL statusCode:401 HTTPVersion:@"HTTP/1.1" headerFields:@{}];
        [self.client URLProtocol:self didReceiveResponse:failResponse cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        [self.client URLProtocolDidFinishLoading:self];
    }];
}

@end

%ctor {
    [NSURLProtocol registerClass:[GSAPortProtocol class]];
}
