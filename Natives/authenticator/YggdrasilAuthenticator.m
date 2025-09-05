#import "YggdrasilAuthenticator.h"
#import "AFNetworking.h"

@implementation YggdrasilAuthenticator

- (id)initWithServer:(NSString *)server username:(NSString *)username password:(NSString *)password {
    NSMutableDictionary *data = [[NSMutableDictionary alloc] init];
    data[@"server"] = server;
    data[@"username"] = username;
    data[@"password"] = password;
    return [self initWithData:data];
}

- (void)loginWithCallback:(Callback)callback {
    NSString *authURL = [NSString stringWithFormat:@"%@/authenticate", self.authData[@"server"]];
    NSDictionary *params = @{
        @"agent": @{@"name": @"Minecraft", @"version": @1},
        @"username": self.authData[@"username"],
        @"password": self.authData[@"password"],
        @"requestUser": @YES
    };
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFJSONRequestSerializer serializer];

    [manager POST:authURL parameters:params headers:nil progress:nil success:^(NSURLSessionDataTask *task, NSDictionary *response) {
        self.authData[@"accessToken"] = response[@"accessToken"];
        NSDictionary *profile = response[@"selectedProfile"];
        self.authData[@"profileId"] = profile[@"id"];
        self.authData[@"username"] = profile[@"name"];
        // Yggdrasil皮肤信息通常通过 profile 属性或单独的 API 获取
        self.authData[@"profilePicURL"] = [NSString stringWithFormat:@"https://mc-heads.net/head/%@/120", profile[@"id"]];
        [self.authData removeObjectForKey:@"password"];
        callback(nil, [self saveChanges]);
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        callback(error.localizedDescription, NO);
    }];
}

- (void)refreshTokenWithCallback:(Callback)callback {
    NSString *refreshURL = [NSString stringWithFormat:@"%@/refresh", self.authData[@"server"]];
    NSDictionary *params = @{
        @"accessToken": self.authData[@"accessToken"],
        @"clientToken": self.authData[@"clientToken"] ?: @""
    };
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFJSONRequestSerializer serializer];

    [manager POST:refreshURL parameters:params headers:nil progress:nil success:^(NSURLSessionDataTask *task, NSDictionary *response) {
        self.authData[@"accessToken"] = response[@"accessToken"];
        callback(nil, [self saveChanges]);
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        callback(error.localizedDescription, NO);
    }];
}

@end