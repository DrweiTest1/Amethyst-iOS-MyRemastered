#import "authenticator/BaseAuthenticator.h"

@interface YggdrasilAuthenticator : BaseAuthenticator

- (id)initWithServer:(NSString *)server username:(NSString *)username password:(NSString *)password;
- (void)loginWithCallback:(Callback)callback;
- (void)refreshTokenWithCallback:(Callback)callback;

@end