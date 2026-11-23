#import <Foundation/Foundation.h>

@interface FindMyVersionSpoofProtocol : NSURLProtocol
@end

@implementation FindMyVersionSpoofProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"FMVSHandled" inRequest:request]) return NO;
    NSString *host = request.URL.host;
    NSString *path = request.URL.path;
    if ([host hasSuffix:@"fmfmobile.icloud.com"]) return YES;
    if ([host hasSuffix:@"fmipmobile.icloud.com"]) {
        if ([path rangeOfString:@"/fmipservice/device/"].location == NSNotFound || ![path hasSuffix:@"/initClient"]) return YES;
    }
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSOperationQueue *queue = [[NSOperationQueue alloc] init];
    [queue addOperationWithBlock:^{
        NSURL *url = self.request.URL;
        NSString *host = url.host;
        NSMutableURLRequest *newReq = [self.request mutableCopy];
        NSData *bodyData = newReq.HTTPBody;
        if (bodyData) {
            id parsed = [NSJSONSerialization JSONObjectWithData:bodyData options:0 error:nil];
            if ([parsed isKindOfClass:[NSDictionary class]]) {
                NSMutableDictionary *bodyDict = [parsed mutableCopy];
                if ([bodyDict[@"clientContext"] isKindOfClass:[NSDictionary class]]) {
                    NSMutableDictionary *clientContext = [bodyDict[@"clientContext"] mutableCopy];
                    if ([host hasSuffix:@"fmfmobile.icloud.com"]) {
                        clientContext[@"osVersion"] = @"7.0";
                        clientContext[@"appVersion"] = @"3.0";
                    } else if ([host hasSuffix:@"fmipmobile.icloud.com"]) {
                        clientContext[@"osVersion"] = @"9.0";
                        clientContext[@"appVersion"] = @"5.0";
                    }
                    bodyDict[@"clientContext"] = clientContext;
                    NSData *reserialized = [NSJSONSerialization dataWithJSONObject:bodyDict options:0 error:nil];
                    if (reserialized) {
                        newReq.HTTPBody = reserialized;
                        NSLog(@"[FindMyVersionSpoof] rewrote clientContext osVersion/appVersion for %@", url.absoluteString);
                    }
                }
            }
        }
        if ([host hasSuffix:@"fmipmobile.icloud.com"] && [self.request valueForHTTPHeaderField:@"X-Apple-Find-API-Ver"]) [newReq setValue:@"3.0" forHTTPHeaderField:@"X-Apple-Find-API-Ver"];
        NSURLResponse *response = nil;
        NSError *error = nil;
        [NSURLProtocol setProperty:@YES forKey:@"FMVSHandled" inRequest:newReq];
        NSData *data = [NSURLConnection sendSynchronousRequest:newReq returningResponse:&response error:&error];
        if (error) {
            [self.client URLProtocol:self didFailWithError:error];
            return;
        }
        [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        [self.client URLProtocol:self didLoadData:data];
        [self.client URLProtocolDidFinishLoading:self];
    }];
}

- (void)stopLoading {
}

@end

%ctor {
    [NSURLProtocol registerClass:[FindMyVersionSpoofProtocol class]];
    NSLog(@"[FindMyVersionSpoof] ctor loaded");
}