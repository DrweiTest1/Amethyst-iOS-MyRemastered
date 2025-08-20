#import <Security/Security.h>
#import "BaseAuthenticator.h"
#import "../LauncherPreferences.h"
#import "../ios_uikit_bridge.h"
#import "../utils.h"

@implementation BaseAuthenticator

static BaseAuthenticator *current = nil;

+ (id)current {
    if (current == nil) {
        [self loadSavedName:getPrefObject(@"internal.selected_account")];
    }
    return current;
}

+ (void)setCurrent:(BaseAuthenticator *)auth {
    current = auth;
}

+ (id)loadSavedName:(NSString *)name {
    NSMutableDictionary *authData = parseJSONFromFile([NSString stringWithFormat:"%s/accounts/%@.json", getenv("POJAV_HOME"), name]);
    if (authData[@"NSErrorObject"] != nil) {
        NSError *error = ((NSError *)authData[@"NSErrorObject"]);
        if (error.code != NSFileReadNoSuchFileError) {
            showDialog(localize(@"Error", nil), error.localizedDescription);
        }
        return nil;
    }

    // If authData explicitly tells type, honor it. Otherwise, fall back to legacy expiresAt heuristic.
    NSString *type = authData[@"type"];
    if (type != nil) {
        if ([type isEqualToString:@"local"]) {
            return [[LocalAuthenticator alloc] initWithData:authData];
        } else if ([type isEqualToString:@"thirdparty"]) {
            Class cls = NSClassFromString(@"ThirdPartyAuthenticator");
            if (cls) {
                return [[cls alloc] initWithData:authData];
            } else {
                // fallback
                return [[MicrosoftAuthenticator alloc] initWithData:authData];
            }
        } else {
            // default to MicrosoftAuthenticator for other online types
            return [[MicrosoftAuthenticator alloc] initWithData:authData];
        }
    } else {
        // legacy: expiresAt == 0 -> local; else Microsoft
        if ([authData[@"expiresAt"] longValue] == 0) {
            return [[LocalAuthenticator alloc] initWithData:authData];
        } else {
            return [[MicrosoftAuthenticator alloc] initWithData:authData];
        }
    }
}

- (id)initWithData:(NSMutableDictionary *)data {
    current = self = [self init];
    self.authData = data;
    return self;
}

- (id)initWithInput:(NSString *)string {
    NSMutableDictionary *data = [[NSMutableDictionary alloc] init];
    data[@"input"] = string;
    return [self initWithData:data];
}

- (void)loginWithCallback:(Callback)callback {
}

- (void)refreshTokenWithCallback:(Callback)callback {
}

- (BOOL)saveChanges {
    NSError *error;

    [self.authData removeObjectForKey:@"input"];

    NSString *newPath = [NSString stringWithFormat:"%s/accounts/%@.json", getenv("POJAV_HOME"), self.authData[@"username"]];
    if (self.authData[@"oldusername"] != nil && ![self.authData[@"username"] isEqualToString:self.authData[@"oldusername"]]) {
        NSString *oldPath = [NSString stringWithFormat:"%s/accounts/%@.json", getenv("POJAV_HOME"), self.authData[@"oldusername"]];
        [NSFileManager.defaultManager moveItemAtPath:oldPath toPath:newPath error:&error];
        // handle error?
    }

    [self.authData removeObjectForKey:@"oldusername"];

    error = saveJSONToFile(self.authData, newPath);

    if (error != nil) {
        showDialog(@"Error while saving file", error.localizedDescription);
    }
    return error == nil;
}

@end
