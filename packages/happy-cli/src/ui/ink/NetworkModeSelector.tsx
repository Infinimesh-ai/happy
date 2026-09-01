import React, { useState } from 'react';
import { Text, useInput, Box } from 'ink';

export type NetworkMode = 'iscp' | 'legacy';

interface NetworkModeSelectorProps {
    onSelect: (mode: NetworkMode) => void;
    onCancel: () => void;
}

/**
 * Zero-credential mode chooser (OPS 2026-08-26 §3.1): with neither an ISCP
 * profile nor a legacy account on the machine, the user picks a network mode
 * explicitly — Happy never defaults into the legacy QR login.
 */
export const NetworkModeSelector: React.FC<NetworkModeSelectorProps> = ({ onSelect, onCancel }) => {
    const [selectedIndex, setSelectedIndex] = useState(0);

    const options: Array<{
        mode: NetworkMode;
        label: string;
        hint: string;
    }> = [
        {
            mode: 'iscp',
            label: 'ISCP enrollment',
            hint: 'managed device invitation — happy iscp enroll <invitation>'
        },
        {
            mode: 'legacy',
            label: 'Legacy Happy account',
            hint: 'QR / browser login against the Happy server'
        }
    ];

    useInput((input, key) => {
        if (key.upArrow) {
            setSelectedIndex(prev => Math.max(0, prev - 1));
        } else if (key.downArrow) {
            setSelectedIndex(prev => Math.min(options.length - 1, prev + 1));
        } else if (key.return) {
            onSelect(options[selectedIndex].mode);
        } else if (key.escape || (key.ctrl && input === 'c')) {
            onCancel();
        } else if (input === '1') {
            setSelectedIndex(0);
            onSelect(options[0].mode);
        } else if (input === '2') {
            setSelectedIndex(1);
            onSelect(options[1].mode);
        }
    });

    return (
        <Box flexDirection="column" paddingY={1}>
            <Box marginBottom={1}>
                <Text>No Happy credentials found. How should this machine join a network?</Text>
            </Box>

            <Box flexDirection="column">
                {options.map((option, index) => {
                    const isSelected = selectedIndex === index;

                    return (
                        <Box key={option.mode} marginY={0}>
                            <Text color={isSelected ? "cyan" : "gray"}>
                                {isSelected ? '› ' : '  '}
                                {index + 1}. {option.label} — {option.hint}
                            </Text>
                        </Box>
                    );
                })}
            </Box>

            <Box marginTop={1}>
                <Text dimColor>Use arrows or 1-2 to select, Enter to confirm, Esc to cancel</Text>
            </Box>
        </Box>
    );
};
