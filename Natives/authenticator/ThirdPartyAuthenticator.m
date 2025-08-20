#import <Security/Security.h>
#import "AFNetworking.h"
#import "BaseAuthenticator.h"
#import "../ios_uikit_bridge.h"
#import "../utils.h"

@implementation ThirdPartyAuthenticator

#pragma mark - Keychain helpers

+ (NSString *)serviceNameForProfile:(NSString *)profileId {
    if (profileId == nil) return nil;
    return [NSString stringWithFormat:@"Amethyst-Auth-%@", profileId];
}

+ (NSDictionary *)tokenDataOfProfile:(NSString *)profileId {
    if (profileId == nil) return nil;
    NSString *service = [self serviceNameForProfile:profileId];
    NSDictionary *query = @{  
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    CFTypeRef dataRef = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &dataRef);
    if (status != errSecSuccess || dataRef == NULL) return nil;
    NSData *data = (__bridge_transfer NSData *)dataRef;
    NSError *err = nil;
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if (err) return nil;
    return dict;
}

+ (BOOL)storeTokenData:(NSDictionary *)tokenData forProfile:(NSString *)profileId {
    if (profileId == nil || tokenData == nil) return NO;
    NSString *service = [self serviceNameForProfile:profileId];
    NSData *payload = [NSJSONSerialization dataWithJSONObject:tokenData options:0 error:NULL];
    NSDictionary *query = @{  
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
    };
    NSDictionary *attributes = @{  
        (__bridge id)kSecValueData: payload,
    };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)[query mutableCopy], NULL);
    if (status == errSecSuccess) return YES;
    if (status == errSecDuplicateItem) {
        status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
        return status == errSecSuccess;
    }
    return NO;
}

+ (BOOL)clearTokenDataOfProfile:(NSString *)profileId {
    if (profileId == nil) return NO;
    NSString *service = [self serviceNameForProfile:profileId];
    NSDictionary *query = @{  
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
    };
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return (status == errSecSuccess || status == errSecItemNotFound);
}

#pragma mark - Auth operations

- (void)loginWithCallback:(Callback)callback {
    callback(localize(@"login.thirdparty.progress.start", nil), YES);

    NSString *server = self.authData[@"server"];
    NSString *username = self.authData[@"username"];
    NSString *password = self.authData[@"password"];
    if (server == nil || username == nil || password == nil) {
        callback(localize(@"login.error.missing_params", nil), NO);
        return;
    }

    if (self.authData[@"clientToken"] == nil) {
        CFUUIDRef uuidRef = CFUUIDCreate(NULL);
        CFStringRef uuidStr = CFUUIDCreateString(NULL, uuidRef);
        self.authData[@"clientToken"] = (__bridge_transfer NSString *)uuidStr;
        CFRelease(uuidRef);
    }

    NSString *url = [NSString stringWithFormat:@"%@/authserver/authenticate", server];

    NSDictionary *json = @{  
        @"agent": @{@"name": @"Minecraft", @"version": @1},
        @"username": username,
        @"password": password,
        @"clientToken": self.authData[@"clientToken"],
        @"requestUser": @YES
    };

    AFHTTPSessionManager *mgr = AFHTTPSessionManager.manager;
    mgr.requestSerializer = [AFJSONRequestSerializer serializer];
    mgr.responseSerializer = [AFJSONResponseSerializer serializer];

    [mgr POST:url parameters:json headers:nil progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        if (![responseObject isKindOfClass:[NSDictionary class]]) {
            callback(localize(@"login.error.invalid_response", nil), NO);
            return;
        }
        NSDictionary *resp = (NSDictionary *)responseObject;
        NSString *accessToken = resp[@"accessToken"];
        NSString *clientToken = resp[@"clientToken"] ?: self.authData[@"clientToken"];
        NSDictionary *selectedProfile = resp[@"selectedProfile"];
        NSString *profileId = selectedProfile[@"id"] ?: @"0";
        NSString *profileName = selectedProfile[@"name"] ?: username;

        if (accessToken == nil) {
            callback(localize(@"login.error.no_token", nil), NO);
            return;
        }

        self.authData[@"username"] = profileName;
        self.authData[@"profileId"] = profileId;
        self.authData[@"accessToken"] = @"0";
        self.authData[@"clientToken"] = clientToken;
        self.authData[@"type"] = @"thirdparty";
        self.authData[@"server"] = server;

        NSDictionary *tokenData = @{  
            @"accessToken": accessToken,
            @"clientToken": clientToken,
            @"username": profileName
        };
        [ThirdPartyAuthenticator storeTokenData:tokenData forProfile:profileId];

        [self saveChanges];

        callback(@{  
            @"profileId": profileId,
            @"username": profileName
        }, YES);

    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        callback(error, NO);
    }];
}

- (void)refreshTokenWithCallback:(Callback)callback {
    callback(localize(@"login.thirdparty.progress.refresh", nil), YES);
    NSString *server = self.authData[@"server"];
    NSString *profileId = self.authData[@"profileId"];
    NSDictionary *saved = nil;
    if (profileId) saved = [ThirdPartyAuthenticator tokenDataOfProfile:profileId];

    if (server == nil || saved == nil) {
        callback(localize(@"login.error.no_refresh", nil), NO);
        return;
    }

    NSString *url = [NSString stringWithFormat:@"%@/authserver/refresh", server];
    NSString *accessToken = saved[@"accessToken"];
    NSString *clientToken = saved[@"clientToken"] ?: self.authData[@"clientToken"];

    NSDictionary *json = @{  
        @"accessToken": accessToken ?: @"",
        @"clientToken": clientToken ?: @""
    };

    AFHTTPSessionManager *mgr = AFHTTPSessionManager.manager;
    mgr.requestSerializer = [AFJSONRequestSerializer serializer];
    mgr.responseSerializer = [AFJSONResponseSerializer serializer];

    [mgr POST:url parameters:json headers:nil progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        NSDictionary *resp = (NSDictionary *)responseObject;
        NSString *newAccess = resp[@"accessToken"];
        NSString *newClient = resp[@"clientToken"] ?: clientToken;
        NSDictionary *selectedProfile = resp[@"selectedProfile"];
        NSString *newProfileId = selectedProfile[@"id"] ?: profileId;

        if (newAccess == nil) {
            callback(localize(@"login.error.no_token", nil), NO);
            return;
        }

        NSDictionary *tokenData = @{  
            @"accessToken": newAccess,
            @"clientToken": newClient,
            @"username": selectedProfile[@"name"] ?: self.authData[@"username"] ?: @""
        };
        [ThirdPartyAuthenticator storeTokenData:tokenData forProfile:newProfileId];

        self.authData[@"profileId"] = newProfileId;
        self.authData[@"clientToken"] = newClient;
        [self saveChanges];

        callback(@{  
            @"profileId": newProfileId
        }, YES);
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        callback(error, NO);
    }];
}

@end