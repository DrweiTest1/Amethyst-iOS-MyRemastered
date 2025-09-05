#import <Foundation/Foundation.h>

typedef void (^Callback)(id status, BOOL success);

@interface BaseAuthenticator : NSObject

@property(nonatomic, strong) NSMutableDictionary *authData;

+ (id)loadSavedName:(NSString *)name;
- (id)initWithData:(NSMutableDictionary *)data;
- (id)initWithInput:(NSString *)input;
- (void)loginWithCallback:(Callback)callback;
- (void)refreshTokenWithCallback:(Callback)callback;
- (BOOL)saveChanges;

@end