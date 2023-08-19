//
//  ContentView.h
//  Gala Runner
//
//  Created by Phillip Tennen on 19/08/2023.
//

#import <Cocoa/Cocoa.h>
#import "NSViewWithTopLeftCoordinateSystem.h"
#import "LogsView.h"

NS_ASSUME_NONNULL_BEGIN

@interface ContentView : NSViewWithTopLeftCoordinateSystem
@property (retain) LogsView* logsView;
@property (retain) NSTask* _Nullable ongoingTask;
@property (atomic, retain) NSMutableString* bufferedData;
@property (retain) NSTextView* statusLabel;
- (instancetype)initWithFrame:(NSRect)frame logsView:(LogsView*)logsView;
@end

NS_ASSUME_NONNULL_END
