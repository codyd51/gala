//
//  LogsView.m
//  Gala Runner
//
//  Created by Phillip Tennen on 19/08/2023.
//

#import "LogsView.h"

@implementation LogsView

- (void)append:(NSString*)text {
    if (!text.length) {
        return;
    }
    
    // Only auto-scroll to display the new text if the user hasn't manually scrolled to view earlier output
    // (Needs to be computed before we add more text just below)
    BOOL shouldAutoScrollToNewContent = CGRectGetMaxY(self.textView.visibleRect) == CGRectGetMaxY(self.textView.frame);
    
    NSDictionary *attrs = @{
            NSForegroundColorAttributeName: [NSColor colorWithRed:0.4 green:1.0 blue:0.4 alpha:1.0],
            NSFontAttributeName: [NSFont monospacedSystemFontOfSize:14 weight:NSFontWeightMedium]
    };
    NSAttributedString* attr = [[NSAttributedString alloc] initWithString:text attributes:attrs];
    [[self.textView textStorage] appendAttributedString:attr];
    
    if (shouldAutoScrollToNewContent) {
        [self.textView scrollRangeToVisible:NSMakeRange(self.textView.attributedString.length, 0)];
    }
    
    [self.textView setNeedsDisplay:YES];
}

- (void)clear {
    self.textView.string = @"";
}

- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        NSScrollView* scrollView = [NSTextView scrollableTextView];
        scrollView.frame = CGRectMake(0, 0, frame.size.width, frame.size.height);

        self.textView = scrollView.documentView;
        self.textView.textContainerInset = NSMakeSize(8, 8);
        self.textView.backgroundColor = [NSColor colorWithWhite:0.1 alpha:1.0];
        [self.textView setTextColor:[NSColor whiteColor]];
        [self.textView setEditable:NO];
        [self addSubview:scrollView];
        [self append:@"Waiting...\n"];
    }
    return self;
}

@end
