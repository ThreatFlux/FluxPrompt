#!/bin/bash

echo "🚀 FluxPrompt + Ollama Integration Setup and Demo"
echo "=================================================="

# Function to check if Ollama is running
check_ollama() {
    if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        echo "✅ Ollama is running"
        return 0
    else
        echo "❌ Ollama is not running"
        return 1
    fi
}

# Function to check if a model exists
check_model() {
    local model=$1
    if ollama list | grep -q "$model"; then
        echo "✅ Model $model is available"
        return 0
    else
        echo "❌ Model $model is not available"
        return 1
    fi
}

echo ""
echo "🔍 Checking Prerequisites..."

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo "❌ Ollama is not installed"
    echo ""
    echo "Please install Ollama first:"
    echo "  Linux/macOS: curl -fsSL https://ollama.com/install.sh | sh"
    echo "  Or visit: https://ollama.com/download"
    exit 1
fi

echo "✅ Ollama is installed"

# Check if Ollama is running
if ! check_ollama; then
    echo ""
    echo "Starting Ollama in the background..."
    ollama serve &
    OLLAMA_PID=$!
    
    echo "Waiting for Ollama to start..."
    sleep 5
    
    if ! check_ollama; then
        echo "❌ Failed to start Ollama"
        echo "Please start Ollama manually: ollama serve"
        exit 1
    fi
fi

echo ""
echo "📦 Checking available models..."

# List available models
echo "Available models:"
ollama list

# Check for required models
MODELS_NEEDED=()
if ! check_model "qwen3:8b"; then
    MODELS_NEEDED+=("qwen3:8b")
fi

if ! check_model "gpt-oss:20b"; then
    MODELS_NEEDED+=("gpt-oss:20b")
fi

# If no suitable models, offer alternatives
if [ ${#MODELS_NEEDED[@]} -eq 2 ]; then
    echo ""
    echo "⚠️  Required models not found. Let's check for alternatives..."
    
    # Look for any qwen3 model
    QWEN_MODEL=$(ollama list | grep -o 'qwen3[^[:space:]]*' | head -1)
    if [ -n "$QWEN_MODEL" ]; then
        echo "✅ Found alternative: $QWEN_MODEL"
        sed -i "s/qwen3:8b/$QWEN_MODEL/g" examples/ollama_integration.rs
        sed -i "s/qwen3:8b/$QWEN_MODEL/g" examples/interactive_demo.rs
        sed -i "s/qwen3:8b/$QWEN_MODEL/g" tests/ollama_tests/comprehensive_test_runner.rs
    fi
    
    # Check if we have any usable model
    if ollama list | grep -q -E "(qwen|llama|mistral|phi|gemma)"; then
        echo "✅ Found compatible models"
    else
        echo "❌ No compatible models found"
        echo ""
        echo "Please pull a model first. Recommended:"
        echo "  ollama pull qwen3:8b    # Fast and efficient"
        echo "  ollama pull llama3.1    # Alternative option"
        exit 1
    fi
fi

echo ""
echo "🎯 Choose a demo to run:"
echo "1. Basic Ollama Integration Demo"
echo "2. Interactive Demo (with user input)"
echo "3. Comprehensive Test Suite"
echo "4. All examples"

read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        echo ""
        echo "🚀 Running Basic Ollama Integration Demo..."
        echo "=========================================="
        cargo run --example ollama_integration
        ;;
    2)
        echo ""
        echo "🎮 Running Interactive Demo..."
        echo "==============================="
        echo "Note: This demo allows you to interact with the system in real-time"
        cargo run --example interactive_demo
        ;;
    3)
        echo ""
        echo "🧪 Running Comprehensive Test Suite..."
        echo "======================================"
        echo "This will run extensive tests against both models"
        echo "Warning: This may take several minutes to complete"
        read -p "Continue? (y/N): " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            cd tests/ollama_tests
            cargo run --bin comprehensive_test_runner
            cd ../..
        else
            echo "Test suite cancelled"
        fi
        ;;
    4)
        echo ""
        echo "🎉 Running All Examples..."
        echo "=========================="
        
        echo "1. Basic Integration Demo:"
        cargo run --example ollama_integration
        
        echo ""
        read -p "Press Enter to continue to Interactive Demo..."
        cargo run --example interactive_demo
        
        echo ""
        read -p "Run comprehensive tests? This may take several minutes (y/N): " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            cd tests/ollama_tests
            cargo run --bin comprehensive_test_runner
            cd ../..
        fi
        ;;
    *)
        echo "Invalid choice. Running basic demo..."
        cargo run --example ollama_integration
        ;;
esac

echo ""
echo "🎉 Demo completed!"
echo ""
echo "📚 Additional Information:"
echo "========================="
echo "• FluxPrompt provides comprehensive protection against prompt injection attacks"
echo "• It integrates seamlessly with Ollama and other LLM services"
echo "• The system blocks malicious prompts while allowing legitimate requests"
echo "• Performance is optimized for production use with minimal latency"
echo ""
echo "📖 Next Steps:"
echo "• Review the generated reports in the current directory"
echo "• Check out the source code in examples/ for integration patterns"
echo "• Customize protection policies for your specific use case"
echo "• Test with your own prompts using the interactive demo"

# Clean up background Ollama if we started it
if [ ! -z "$OLLAMA_PID" ]; then
    echo ""
    echo "Stopping background Ollama process..."
    kill $OLLAMA_PID 2>/dev/null
fi