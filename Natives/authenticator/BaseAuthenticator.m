#import "BaseAuthenticator.h"
#import "LocalAuthenticator.h"
#import "MicrosoftAuthenticator.h"
#import "YggdrasilAuthenticator.h"

@implementation BaseAuthenticator

+ (id)loadSavedName:(NSString *)name {
    NSString *path = [NSString stringWithFormat:@"%s/accounts/%@.json", getenv("POJAV_HOME"), name];
    NSMutableDictionary *authData = [NSMutableDictionary dictionaryWithContentsOfFile:path];
    if ([authData[@"server"] length] > 0) {
        return [[YggdrasilAuthenticator alloc] initWithData:authData];
    } else if ([authData[@"xuid"] length] > 0) {
        return [[MicrosoftAuthenticator alloc] initWithData:authData];
    } else {
        return [[LocalAuthenticator alloc] initWithData:authData];
    }
}

- (id)initWithData:(NSMutableDictionary *)data {
    self = [super init];
    self.authData = data;
    return self;
}

- (id)initWithInput:(NSString *)string {
    NSMutableDictionary *data = [[NSMutableDictionary alloc] init];
    data[@"input"] = string;
    return [self initWithData:data];
}

- (void)loginWithCallback:(Callback)callback {}
- (void)refreshTokenWithCallback:(Callback)callback {}
- (BOOL)saveChanges {
    NSError *error;
    [self.authData removeObjectForKey:@"input"];
    NSString *newPath = [NSString stringWithFormat:@"%s/accounts/%@.json", getenv("POJAV_HOME"), self.authData[@"username"]];
    if (self.authData[@"oldusername"] != nil && ![self.authData[@"username"] isEqualToString:self.authData[@"oldusername"]]) {
        NSString *oldPath = [NSString stringWithFormat:@"%s/accounts/%@.json", getenv("POJAV_HOME"), self.authData[@"oldusername"]];
        [[NSFileManager defaultManager] removeItemAtPath:oldPath error:nil];
    }
    BOOL result = [self.authData writeToFile:newPath atomically:YES];
    if (!result) {
        NSLog(@"Failed to save account data: %@", error);
    }
    return result;
}

@end