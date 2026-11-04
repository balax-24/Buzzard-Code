import os
import unittest
import tempfile
import shutil
from security_agent.tools.filesystem import file_list, file_read, file_write, file_search, get_safe_path, set_active_workspace
from security_agent.tools.registry import ToolRegistry

class TestFilesystemTools(unittest.TestCase):
    def setUp(self):
        # We need to back up the current workspace or temporarily override os.path.abspath("data/workspace")
        # To do this safely, we can patch the workspace directory or mock it.
        # But wait, our get_safe_path uses os.path.abspath("data/workspace").
        # If we temporarily change the current working directory to a temp directory,
        # "data/workspace" will be resolved relative to that temp directory, keeping our tests isolated!
        self.test_dir = tempfile.mkdtemp()
        self.old_cwd = os.getcwd()
        os.chdir(self.test_dir)
        self.workspace = os.path.abspath("data/workspace")
        os.makedirs(self.workspace, exist_ok=True)
        set_active_workspace(self.workspace)

    def tearDown(self):
        set_active_workspace(None)
        os.chdir(self.old_cwd)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_get_safe_path(self):
        # Test default
        self.assertEqual(get_safe_path("."), self.workspace)
        
        # Test relative path
        self.assertEqual(get_safe_path("test.txt"), os.path.join(self.workspace, "test.txt"))
        
        # Test absolute /workspace path
        self.assertEqual(get_safe_path("/workspace/test.txt"), os.path.join(self.workspace, "test.txt"))
        
        # Test path traversal escaping
        with self.assertRaises(PermissionError):
            get_safe_path("../escaped.txt")
            
        with self.assertRaises(PermissionError):
            get_safe_path("/etc/passwd")

    def test_file_write_and_read(self):
        # Write
        res = file_write("sub/test.txt", "Hello Workspace!")
        self.assertIn("Successfully wrote", res)
        
        # Verify exists
        full_path = os.path.join(self.workspace, "sub/test.txt")
        self.assertTrue(os.path.exists(full_path))
        
        # Read
        content = file_read("sub/test.txt")
        self.assertEqual(content, "Hello Workspace!")
        
        # Read non-existent
        res = file_read("doesnotexist.txt")
        self.assertIn("Error", res)

    def test_file_list(self):
        file_write("a.txt", "content a")
        file_write("sub/b.txt", "content b")
        
        # List root
        res = file_list(".")
        self.assertIn("a.txt", res)
        self.assertIn("[DIR] sub", res)
        
        # List sub
        res = file_list("sub")
        self.assertIn("b.txt", res)
        self.assertNotIn("a.txt", res)
        
        # List file
        res = file_list("a.txt")
        self.assertIn("Error", res)

    def test_file_search(self):
        file_write("a.py", "import os\nprint('hello')")
        file_write("sub/b.py", "import sys\nprint('world')")
        file_write("other.txt", "just plain text")
        
        # Search by filename glob
        res = file_search("*.py")
        self.assertIn("a.py", res)
        self.assertIn("sub/b.py", res)
        self.assertNotIn("other.txt", res)
        
        # Search by content query
        res = file_search("print")
        self.assertIn("a.py", res)
        self.assertIn("sub/b.py", res)
        self.assertNotIn("other.txt", res)

        # Search non-existent
        res = file_search("missing_pattern", "non_existent_folder")
        self.assertIn("Error", res)

    def test_registry_integration(self):
        registry = ToolRegistry()
        from security_agent.tools.filesystem import register_filesystem_tools
        register_filesystem_tools(registry)
        
        self.assertIn("file.list", registry.tools)
        self.assertIn("file.read", registry.tools)
        self.assertIn("file.write", registry.tools)
        self.assertIn("file.search", registry.tools)

    def test_file_write_fallback(self):
        from unittest.mock import patch, mock_open
        # Mocking open to fail on write, trigger fallback
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            res = file_write("test_fallback.txt", "Fallback Content")
            self.assertIn("using fallback", res)
            # Verify file actually has the contents
            content = file_read("test_fallback.txt")
            self.assertEqual(content, "Fallback Content")

    def test_file_read_fallback(self):
        from unittest.mock import patch
        # Write content successfully first
        file_write("test_read_fallback.txt", "Read Fallback Content")
        # Mocking open to fail on read, trigger fallback
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            content = file_read("test_read_fallback.txt")
            self.assertEqual(content, "Read Fallback Content")


