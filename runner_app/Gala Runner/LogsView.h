//
//  LogsView.h
//  Gala Runner
//
//  Created by Phillip Tennen on 19/08/2023.
//

#import <Cocoa/Cocoa.h>
#import "NSViewWithTopLeftCoordinateSystem.h"

NS_ASSUME_NONNULL_BEGIN

@interface LogsView : NSViewWithTopLeftCoordinateSystem
@property (retain) NSTextView* textView;
- (void)clear;
- (void)append:(NSString*)text;
- (instancetype)initWithFrame:(NSRect)frame;
@end

NS_ASSUME_NONNULL_END
